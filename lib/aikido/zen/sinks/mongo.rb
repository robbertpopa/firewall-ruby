# frozen_string_literal: true

module Aikido::Zen
  module Sinks
    module Mongo
      SINK = Sinks.add("mongo", scanners: [Scanners::NoSQLInjectionScanner])

      module Helpers
        def self.scan(collection, operation, **contexts)
          SINK.scan(
            operation: operation,
            collection: collection_name(collection),
            contexts: contexts.compact
          )
        end

        def self.collection_name(collection)
          collection.name if collection.respond_to?(:name)
        rescue
          nil
        end
      end

      def self.load_sinks!
        return unless Aikido::Zen.satisfy("mongo")
        return unless defined?(::Mongo::Collection)

        ::Mongo::Collection.class_eval do
          extend Sinks::DSL

          sink_before :find do |filter = {}, *_args, **_kwargs|
            Helpers.scan(self, "find", filter: filter)
          end

          sink_before :aggregate do |pipeline = [], *_args, **_kwargs|
            Helpers.scan(self, "aggregate", pipeline: pipeline)
          end

          sink_before :update_one do |filter, update, *_args, **_kwargs|
            Helpers.scan(self, "update_one", filter: filter, update: update)
          end

          sink_before :update_many do |filter, update, *_args, **_kwargs|
            Helpers.scan(self, "update_many", filter: filter, update: update)
          end

          sink_before :replace_one do |filter, replacement, *_args, **_kwargs|
            Helpers.scan(self, "replace_one", filter: filter, document: replacement)
          end

          sink_before :delete_one do |filter = {}, *_args, **_kwargs|
            Helpers.scan(self, "delete_one", filter: filter)
          end

          sink_before :delete_many do |filter = {}, *_args, **_kwargs|
            Helpers.scan(self, "delete_many", filter: filter)
          end

          sink_before :find_one_and_update do |filter, update, *_args, **_kwargs|
            Helpers.scan(self, "find_one_and_update", filter: filter, update: update)
          end

          sink_before :find_one_and_replace do |filter, replacement, *_args, **_kwargs|
            Helpers.scan(self, "find_one_and_replace", filter: filter, document: replacement)
          end

          sink_before :find_one_and_delete do |filter = {}, *_args, **_kwargs|
            Helpers.scan(self, "find_one_and_delete", filter: filter)
          end

          sink_before :insert_one do |document, *_args, **_kwargs|
            Helpers.scan(self, "insert_one", document: document)
          end

          sink_before :insert_many do |documents = [], *_args, **_kwargs|
            Helpers.scan(self, "insert_many", document: documents)
          end
        end
      end
    end
  end
end

Aikido::Zen::Sinks::Mongo.load_sinks!
