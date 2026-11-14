# frozen_string_literal: true

require "set"
require_relative "../attack"

module Aikido::Zen
  module Scanners
    class NoSQLInjectionScanner
      FORBIDDEN_OPERATORS = Set.new(%w[$where $function $accumulator]).freeze
      FILTER_LOGICAL_OPERATORS = Set.new(%w[$and $or $nor]).freeze
      FILTER_FIELD_DENYLIST = Set.new(%w[$ne $not]).freeze

      def self.skips_on_nil_context?
        false
      end

      def self.call(contexts:, collection:, sink:, context:, operation:)
        scanner = new(contexts)
        finding = scanner.scan!
        return if finding.nil?

        Attacks::NoSQLInjectionAttack.new(
          collection: collection,
          scan_context: finding[:context],
          reason: finding[:reason],
          key: finding[:key],
          location: finding[:location],
          shape: scanner.shape,
          sink: sink,
          context: context,
          operation: "#{sink.operation}.#{operation}",
          stack: Aikido::Zen.clean_stack_trace
        )
      end

      def initialize(contexts)
        @contexts = contexts.to_h
      end

      def scan!
        @contexts.each do |name, payload|
          seen = Set.new

          finding = case name.to_sym
          when :filter
            scan_filter(payload, path: "$", seen: seen)
          when :update
            scan_update(payload, path: "$", seen: seen)
          when :pipeline
            scan_pipeline(payload, path: "$", seen: seen)
          else
            scan_document(payload, path: "$", seen: seen)
          end

          return finding if finding
        end

        nil
      end

      def shape(value = @contexts, seen = Set.new)
        if (hash = hash_from(value))
          return "<circular>" if seen.include?(hash.object_id)

          seen << hash.object_id
          return hash.to_h { |key, child| [key.to_s, shape(child, seen)] }
        end

        if (array = array_from(value))
          return "<circular>" if seen.include?(array.object_id)

          seen << array.object_id
          return array.map { |child| shape(child, seen) }
        end

        value.class.name
      end

      private

      def scan_filter(payload, path:, seen:)
        hash = hash_from(payload)
        return if hash.nil? || circular?(hash, seen)

        hash.each do |raw_key, value|
          key = raw_key.to_s

          finding = if operator?(key)
            scan_filter_operator(key, value, path: path, seen: seen)
          else
            scan_filter_field_value(value, path: append(path, key), seen: seen)
          end
          return finding if finding
        end

        nil
      end

      def scan_filter_operator(operator, value, path:, seen:)
        if forbidden_operator?(operator)
          return finding(context: "filter", reason: "forbidden_operator", key: operator, path: append(path, operator))
        end

        if FILTER_LOGICAL_OPERATORS.include?(operator)
          return scan_array(value, path: append(path, operator), seen: seen) do |child, child_path|
            scan_filter(child, path: child_path, seen: seen)
          end
        end

        scan_expression(value, context: "filter", path: append(path, operator), seen: seen)
      end

      def scan_filter_field_value(value, path:, seen:)
        hash = hash_from(value)

        unless hash&.keys&.any? { |key| operator?(key.to_s) }
          if hash
            return scan_filter(hash, path: path, seen: seen)
          end

          return scan_array(value, path: path, seen: seen) do |child, child_path|
            scan_filter_field_value(child, path: child_path, seen: seen)
          end
        end

        hash.each do |raw_operator, child|
          operator = raw_operator.to_s

          if forbidden_operator?(operator)
            return finding(context: "filter", reason: "forbidden_operator", key: operator, path: append(path, operator))
          end

          if FILTER_FIELD_DENYLIST.include?(operator)
            return finding(context: "filter", reason: "blocked_field_operator", key: operator, path: append(path, operator))
          end

          finding = if operator == "$elemMatch"
            scan_filter(child, path: append(path, operator), seen: seen)
          else
            scan_expression(child, context: "filter", path: append(path, operator), seen: seen)
          end
          return finding if finding
        end

        nil
      end

      def scan_update(payload, path:, seen:)
        hash = hash_from(payload)
        return if hash.nil? || circular?(hash, seen)

        hash.each do |raw_key, value|
          key = raw_key.to_s

          if forbidden_operator?(key)
            return finding(context: "update", reason: "forbidden_operator", key: key, path: append(path, key))
          end

          finding = scan_expression(value, context: "update", path: append(path, key), seen: seen)
          return finding if finding
        end

        nil
      end

      def scan_pipeline(payload, path:, seen:)
        scan_array(payload, path: path, seen: seen) do |stage, stage_path|
          stage_hash = hash_from(stage)

          if stage_hash
            next if circular?(stage_hash, seen)

            stage_hash.each do |raw_stage, body|
              stage_name = raw_stage.to_s

              if forbidden_operator?(stage_name)
                return finding(context: "pipeline", reason: "forbidden_operator", key: stage_name, path: append(stage_path, stage_name))
              end

              finding = if stage_name == "$match"
                scan_filter(body, path: append(stage_path, stage_name), seen: seen)
              else
                scan_expression(body, context: "pipeline", path: append(stage_path, stage_name), seen: seen)
              end
              return finding if finding
            end

            next
          end

          scan_expression(stage, context: "pipeline", path: stage_path, seen: seen)
        end

        nil
      end

      def scan_expression(payload, context:, path:, seen:)
        if (hash = hash_from(payload))
          return if circular?(hash, seen)

          hash.each do |raw_key, value|
            key = raw_key.to_s

            if forbidden_operator?(key)
              return finding(context: context, reason: "forbidden_operator", key: key, path: append(path, key))
            end

            finding = scan_expression(value, context: context, path: append(path, key), seen: seen)
            return finding if finding
          end

          return nil
        end

        scan_array(payload, path: path, seen: seen) do |child, child_path|
          scan_expression(child, context: context, path: child_path, seen: seen)
        end
      end

      def scan_document(payload, path:, seen:)
        if (hash = hash_from(payload))
          return if circular?(hash, seen)

          hash.each do |raw_key, value|
            key = raw_key.to_s

            if operator?(key)
              return finding(context: "document", reason: "operator_not_allowed", key: key, path: append(path, key))
            end

            finding = scan_document(value, path: append(path, key), seen: seen)
            return finding if finding
          end

          return nil
        end

        scan_array(payload, path: path, seen: seen) do |child, child_path|
          scan_document(child, path: child_path, seen: seen)
        end
      end

      def scan_array(payload, path:, seen:)
        array = array_from(payload)
        return if array.nil? || circular?(array, seen)

        array.each_with_index do |child, index|
          child_path = "#{path}[#{index}]"
          finding = yield(child, child_path)
          return finding if finding
        end

        nil
      end

      def circular?(value, seen)
        return true if seen.include?(value.object_id)

        seen << value.object_id
        false
      end

      def operator?(key)
        key.start_with?("$")
      end

      def forbidden_operator?(key)
        operator?(key) && FORBIDDEN_OPERATORS.include?(key)
      end

      def append(path, segment)
        "#{path}.#{segment}"
      end

      def finding(context:, reason:, key:, path:)
        {
          context: context,
          reason: reason,
          key: key,
          location: path
        }
      end

      def hash_from(value)
        value.to_hash if value.respond_to?(:to_hash)
      rescue
        nil
      end

      def array_from(value)
        value.to_ary if value.respond_to?(:to_ary)
      rescue
        nil
      end
    end
  end
end
