# frozen_string_literal: true

require "test_helper"

class Aikido::Zen::Scanners::NoSQLInjectionScannerTest < ActiveSupport::TestCase
  Scanner = Aikido::Zen::Scanners::NoSQLInjectionScanner

  def assert_attack(context, payload, reason = "payload was not blocked")
    assert scan(context, payload), reason
  end

  def refute_attack(context, payload, reason = "payload was blocked")
    refute scan(context, payload), reason
  end

  def scan(context, payload)
    Scanner.new({context => payload}).scan!
  end

  test "allows simple equality filters" do
    refute_attack :filter, {email: "a@b.com"}
  end

  test "allows safe field-level operators" do
    refute_attack :filter, {age: {"$gt" => 18}}
  end

  test "allows logical filter operators" do
    refute_attack :filter, {
      "$or" => [
        {status: "A"},
        {qty: {"$lt" => 30}}
      ]
    }
  end

  test "allows safe updates" do
    refute_attack :update, {"$set" => {name: "john"}}
  end

  test "allows simple aggregation pipelines" do
    refute_attack :pipeline, [{"$match" => {status: "A"}}]
  end

  test "allows unknown operators and lets mongo validate" do
    refute_attack :pipeline, [{"$unknownStage" => {x: 1}}]
    refute_attack :update, {"$unknownUpdate" => {x: 1}}
  end

  test "blocks high-risk field-level operators" do
    assert_attack :filter, {email: {"$ne" => nil}}
  end

  test "blocks forbidden javascript operators" do
    assert_attack :filter, {"$where" => "this.password && this.password.length > 0"}
  end

  test "blocks forbidden operators in pipelines" do
    assert_attack :pipeline, [{"$project" => {score: {"$function" => {}}}}]
    assert_attack :pipeline, [{"$project" => {score: {"$accumulator" => {}}}}]
  end

  test "blocks injected operators in insert/replacement documents" do
    assert_attack :document, {"$bad" => "value"}
    assert_attack :document, {"$set" => {name: "john"}}
  end

  test "returns a NoSQL attack with redacted shape metadata" do
    sink = Aikido::Zen::Sink.new("mongo", scanners: [NOOP])

    attack = Scanner.call(
      contexts: {filter: {email: {"$ne" => "secret@example.com"}}},
      collection: "users",
      sink: sink,
      context: nil,
      operation: "find"
    )

    assert_kind_of Aikido::Zen::Attacks::NoSQLInjectionAttack, attack
    assert_equal "nosql_injection", attack.kind
    assert_equal "users", attack.collection
    assert_equal "blocked_field_operator", attack.reason
    assert_equal "$ne", attack.key

    metadata = attack.metadata
    assert_equal "users", metadata[:collection]
    assert_equal "filter", metadata[:context]
    assert_equal "blocked_field_operator", metadata[:reason]
    assert_equal "$ne", metadata[:key]

    shape_string = metadata[:shape].inspect
    refute_includes shape_string, "a@b.com"
    refute_includes shape_string, "secret@example.com"
    assert_includes shape_string, "String"
  end
end
