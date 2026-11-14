# frozen_string_literal: true

require "test_helper"

class Aikido::Zen::Sinks::MongoTest < ActiveSupport::TestCase
  include SinkAttackHelpers

  setup do
    Object.send(:remove_const, :Mongo) if defined?(::Mongo)

    mongo = Module.new
    collection = Class.new do
      attr_reader :name, :calls

      def initialize(name = "users")
        @name = name
        @calls = []
      end

      def find(filter = {}, options = {})
        @calls << [:find, filter, options]
        :find_ok
      end

      def aggregate(pipeline = [], options = {})
        @calls << [:aggregate, pipeline, options]
        :aggregate_ok
      end

      def update_one(filter, update, options = {})
        @calls << [:update_one, filter, update, options]
        :update_one_ok
      end

      def update_many(filter, update, options = {})
        @calls << [:update_many, filter, update, options]
        :update_many_ok
      end

      def replace_one(filter, replacement, options = {})
        @calls << [:replace_one, filter, replacement, options]
        :replace_one_ok
      end

      def delete_one(filter = {}, options = {})
        @calls << [:delete_one, filter, options]
        :delete_one_ok
      end

      def delete_many(filter = {}, options = {})
        @calls << [:delete_many, filter, options]
        :delete_many_ok
      end

      def find_one_and_update(filter, update, options = {})
        @calls << [:find_one_and_update, filter, update, options]
        :find_one_and_update_ok
      end

      def find_one_and_replace(filter, replacement, options = {})
        @calls << [:find_one_and_replace, filter, replacement, options]
        :find_one_and_replace_ok
      end

      def find_one_and_delete(filter = {}, options = {})
        @calls << [:find_one_and_delete, filter, options]
        :find_one_and_delete_ok
      end

      def insert_one(document, options = {})
        @calls << [:insert_one, document, options]
        :insert_one_ok
      end

      def insert_many(documents, options = {})
        @calls << [:insert_many, documents, options]
        :insert_many_ok
      end
    end

    mongo.const_set(:Collection, collection)
    Object.const_set(:Mongo, mongo)

    satisfies_only_mongo = ->(name, *) { name == "mongo" }

    Aikido::Zen.stub(:satisfy, satisfies_only_mongo) do
      Aikido::Zen::Sinks::Mongo.load_sinks!
    end

    @collection = ::Mongo::Collection.new("users")
    @sink = Aikido::Zen::Sinks::Mongo::SINK
  end

  teardown do
    Object.send(:remove_const, :Mongo) if defined?(::Mongo)
  end

  def assert_scans(method_name, args:, operation:, contexts:, result:)
    scanner = Struct.new(:captured) do
      def call(**data)
        self.captured = data
        nil
      end

      def skips_on_nil_context?
        false
      end
    end.new

    @sink.stub :scanners, [scanner] do
      assert_equal result, @collection.public_send(method_name, *args)
    end

    assert_equal(
      {
        contexts: contexts,
        collection: "users",
        operation: operation,
        sink: @sink,
        context: nil
      },
      scanner.captured
    )
  end

  test "patches all supported collection methods and scans their payloads" do
    assert_scans :find,
      args: [{email: "a@b.com"}],
      operation: "find",
      contexts: {filter: {email: "a@b.com"}},
      result: :find_ok

    assert_scans :aggregate,
      args: [[{"$match" => {status: "A"}}]],
      operation: "aggregate",
      contexts: {pipeline: [{"$match" => {status: "A"}}]},
      result: :aggregate_ok

    assert_scans :update_one,
      args: [{_id: 1}, {"$set" => {name: "john"}}],
      operation: "update_one",
      contexts: {filter: {_id: 1}, update: {"$set" => {name: "john"}}},
      result: :update_one_ok

    assert_scans :update_many,
      args: [{status: "A"}, {"$set" => {status: "B"}}],
      operation: "update_many",
      contexts: {filter: {status: "A"}, update: {"$set" => {status: "B"}}},
      result: :update_many_ok

    assert_scans :replace_one,
      args: [{_id: 1}, {name: "new"}],
      operation: "replace_one",
      contexts: {filter: {_id: 1}, document: {name: "new"}},
      result: :replace_one_ok

    assert_scans :delete_one,
      args: [{_id: 1}],
      operation: "delete_one",
      contexts: {filter: {_id: 1}},
      result: :delete_one_ok

    assert_scans :delete_many,
      args: [{status: "A"}],
      operation: "delete_many",
      contexts: {filter: {status: "A"}},
      result: :delete_many_ok

    assert_scans :find_one_and_update,
      args: [{_id: 1}, {"$set" => {name: "john"}}],
      operation: "find_one_and_update",
      contexts: {filter: {_id: 1}, update: {"$set" => {name: "john"}}},
      result: :find_one_and_update_ok

    assert_scans :find_one_and_replace,
      args: [{_id: 1}, {name: "john"}],
      operation: "find_one_and_replace",
      contexts: {filter: {_id: 1}, document: {name: "john"}},
      result: :find_one_and_replace_ok

    assert_scans :find_one_and_delete,
      args: [{_id: 1}],
      operation: "find_one_and_delete",
      contexts: {filter: {_id: 1}},
      result: :find_one_and_delete_ok

    assert_scans :insert_one,
      args: [{name: "john"}],
      operation: "insert_one",
      contexts: {document: {name: "john"}},
      result: :insert_one_ok

    assert_scans :insert_many,
      args: [[{name: "a"}, {name: "b"}]],
      operation: "insert_many",
      contexts: {document: [{name: "a"}, {name: "b"}]},
      result: :insert_many_ok
  end

  test "safe Mongo payloads are allowed and still call original methods" do
    refute_attack do
      result = @collection.update_one({_id: 1}, {"$set" => {email: "safe@example.com"}})
      assert_equal :update_one_ok, result
    end

    assert_equal [:update_one, {_id: 1}, {"$set" => {email: "safe@example.com"}}, {}], @collection.calls.last
  end

  test "malicious Mongo payloads are blocked" do
    assert_attack Aikido::Zen::Attacks::NoSQLInjectionAttack do
      @collection.find({email: {"$ne" => nil}})
    end

    assert_attack Aikido::Zen::Attacks::NoSQLInjectionAttack do
      @collection.insert_one({"$set" => {admin: true}})
    end
  end

  test "does not auto-require mongo when collection is not already loaded" do
    Object.send(:remove_const, :Mongo) if defined?(::Mongo)

    satisfies_only_mongo = ->(name, *) { name == "mongo" }

    Aikido::Zen.stub(:satisfy, satisfies_only_mongo) do
      assert_nothing_raised do
        Aikido::Zen::Sinks::Mongo.load_sinks!
      end
    end

    refute defined?(::Mongo::Collection)
  end
end
