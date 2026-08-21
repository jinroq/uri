# frozen_string_literal: true
require "test/unit"
require "uri"
require "uri/whatwg_parser"

# Phase 1: absolute http/https URLs only.
#
# URI::WHATWG_Parser#split must return the same 9-element contract as
# URI::RFC3986_Parser#split:
#
#   [scheme, userinfo, host, port, registry, path, opaque, query, fragment]
#
# so that URI.for(*parser.split(uri), parser) keeps working unmodified.
# registry and opaque are always nil for absolute http/https URLs.
class URI::TestWHATWGParser < Test::Unit::TestCase
  def setup
    @parser = URI::WHATWG_Parser.new
  end

  # --- scheme ---

  def test_split_returns_scheme_for_simple_http_url
    assert_equal("http", @parser.split("http://example.com")[0])
  end

  def test_split_lowercases_uppercase_scheme
    assert_equal("http", @parser.split("HTTP://example.com")[0])
  end

  def test_split_lowercases_mixed_case_scheme
    assert_equal("https", @parser.split("HtTpS://example.com")[0])
  end

  def test_split_treats_scheme_less_relative_path_as_relative_reference
    assert_equal(
      [nil, nil, nil, nil, nil, "example.com/foo", nil, nil, nil],
      @parser.split("example.com/foo")
    )
  end

  # --- host & path ---

  def test_split_returns_host_for_simple_http_url
    assert_equal("example.com", @parser.split("http://example.com")[2])
  end

  def test_split_lowercases_uppercase_host
    assert_equal("example.com", @parser.split("http://EXAMPLE.COM")[2])
  end

  def test_split_normalizes_missing_path_to_root
    assert_equal("/", @parser.split("http://example.com")[5])
  end

  def test_split_keeps_root_path_with_trailing_slash
    assert_equal("/", @parser.split("http://example.com/")[5])
  end

  def test_split_returns_multi_segment_path
    assert_equal("/foo/bar", @parser.split("http://example.com/foo/bar")[5])
  end

  def test_split_keeps_trailing_slash_for_path
    assert_equal("/foo/", @parser.split("http://example.com/foo/")[5])
  end

  # --- port ---

  def test_split_returns_nil_port_when_omitted
    assert_nil(@parser.split("http://example.com/")[3])
  end

  def test_split_normalizes_default_http_port_to_nil
    assert_nil(@parser.split("http://example.com:80/")[3])
  end

  def test_split_normalizes_default_https_port_to_nil
    assert_nil(@parser.split("https://example.com:443/")[3])
  end

  def test_split_returns_explicit_non_default_port
    assert_equal("8080", @parser.split("http://example.com:8080/")[3])
  end

  def test_split_accepts_minimum_port_boundary
    assert_equal("0", @parser.split("http://example.com:0/")[3])
  end

  def test_split_accepts_maximum_port_boundary
    assert_equal("65535", @parser.split("http://example.com:65535/")[3])
  end

  def test_split_raises_for_port_above_maximum_boundary
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://example.com:65536/")
    end
  end

  def test_split_raises_for_non_numeric_port
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://example.com:abc/")
    end
  end

  # --- userinfo ---

  def test_split_returns_userinfo_when_user_and_password_present
    assert_equal("user:pass", @parser.split("http://user:pass@example.com/")[1])
  end

  def test_split_returns_userinfo_with_user_only
    assert_equal("user", @parser.split("http://user@example.com/")[1])
  end

  def test_split_returns_nil_userinfo_when_absent
    assert_nil(@parser.split("http://example.com/")[1])
  end

  # --- query ---

  def test_split_returns_query_when_present
    assert_equal("bar=1", @parser.split("http://example.com/foo?bar=1")[7])
  end

  def test_split_returns_nil_query_when_absent
    assert_nil(@parser.split("http://example.com/foo")[7])
  end

  def test_split_returns_empty_query_when_question_mark_only
    assert_equal("", @parser.split("http://example.com/foo?")[7])
  end

  # --- fragment ---

  def test_split_returns_fragment_when_present
    assert_equal("baz", @parser.split("http://example.com/foo#baz")[8])
  end

  def test_split_returns_nil_fragment_when_absent
    assert_nil(@parser.split("http://example.com/foo")[8])
  end

  def test_split_returns_empty_fragment_when_hash_only
    assert_equal("", @parser.split("http://example.com/foo#")[8])
  end

  def test_split_query_and_fragment_together
    scheme, _, _, _, _, path, _, query, fragment = @parser.split("http://example.com/foo?bar=1#baz")
    assert_equal("http", scheme)
    assert_equal("/foo", path)
    assert_equal("bar=1", query)
    assert_equal("baz", fragment)
  end

  def test_split_fragment_may_contain_question_mark
    _, _, _, _, _, _, _, query, fragment = @parser.split("http://example.com/foo?bar=1#section?weird")
    assert_equal("bar=1", query)
    assert_equal("section?weird", fragment)
  end

  # --- registry / opaque (always nil for absolute http/https URLs) ---

  def test_split_returns_nil_registry
    assert_nil(@parser.split("http://example.com/")[4])
  end

  def test_split_returns_nil_opaque
    assert_nil(@parser.split("http://example.com/")[6])
  end

  # --- full contract shape ---

  def test_split_returns_nine_element_array
    assert_equal(9, @parser.split("http://example.com/").size)
  end

  def test_split_full_example
    result = @parser.split("http://user:pass@example.com:8080/foo/bar?q=1#frag")
    assert_equal(
      ["http", "user:pass", "example.com", "8080", nil, "/foo/bar", nil, "q=1", "frag"],
      result
    )
  end

  # --- parse ---

  def test_parse_returns_uri_http_instance_for_http_scheme
    assert_instance_of(URI::HTTP, @parser.parse("http://example.com/"))
  end

  def test_parse_returns_uri_https_instance_for_https_scheme
    assert_instance_of(URI::HTTPS, @parser.parse("https://example.com/"))
  end

  def test_parse_sets_scheme_host_path_query_fragment
    result = @parser.parse("http://example.com/foo?bar=1#baz")
    assert_equal("http", result.scheme)
    assert_equal("example.com", result.host)
    assert_equal("/foo", result.path)
    assert_equal("bar=1", result.query)
    assert_equal("baz", result.fragment)
  end

  def test_parse_sets_user_and_password
    result = @parser.parse("http://user:pass@example.com/")
    assert_equal("user", result.user)
    assert_equal("pass", result.password)
  end

  def test_parse_sets_explicit_non_default_port
    assert_equal(8080, @parser.parse("http://example.com:8080/").port)
  end

  def test_parse_fills_in_default_port_when_omitted
    assert_equal(80, @parser.parse("http://example.com/").port)
  end

  # --- regexp ---

  def test_regexp_returns_a_hash
    assert_instance_of(Hash, @parser.regexp)
  end

  def test_regexp_scheme_matches_valid_scheme
    assert_match(@parser.regexp[:SCHEME], "http")
  end

  def test_regexp_scheme_rejects_scheme_starting_with_digit
    refute_match(@parser.regexp[:SCHEME], "1http")
  end

  def test_regexp_allows_generic_setter_to_change_host
    uri = @parser.parse("http://example.com/")
    uri.host = "other.example.com"
    assert_equal("other.example.com", uri.host)
  end

  def test_regexp_setter_rejects_invalid_host
    uri = @parser.parse("http://example.com/")
    assert_raise(URI::InvalidComponentError) do
      uri.host = "invalid host with spaces"
    end
  end

  # --- join ---

  def test_join_with_single_absolute_uri
    assert_equal("http://example.com/foo", @parser.join("http://example.com/foo").to_s)
  end

  def test_join_two_absolute_uris_returns_the_latter
    result = @parser.join("http://example.com/foo", "http://example.org/bar")
    assert_equal("http://example.org/bar", result.to_s)
  end

  # --- split: relative references (no scheme) ---
  #
  # These feed Generic#merge, which parses the second argument on its own
  # (via parser.parse) and merges it against the base with the standard
  # RFC2396 Section 5.2 algorithm. A missing path is left as "" here
  # (not normalized to "/"), since Generic#merge treats an empty rel.path
  # as "no path given" (RFC2396 5.2, step 2).

  def test_split_treats_absolute_path_reference_as_relative_reference
    assert_equal(
      [nil, nil, nil, nil, nil, "/foo/bar", nil, nil, nil],
      @parser.split("/foo/bar")
    )
  end

  def test_split_treats_network_path_reference_as_relative_reference
    assert_equal(
      [nil, nil, "example.com", nil, nil, "/foo", nil, nil, nil],
      @parser.split("//example.com/foo")
    )
  end

  def test_split_relative_reference_with_query_only
    assert_equal(
      [nil, nil, nil, nil, nil, "", nil, "q=1", nil],
      @parser.split("?q=1")
    )
  end

  def test_split_relative_reference_with_fragment_only
    assert_equal(
      [nil, nil, nil, nil, nil, "", nil, nil, "frag"],
      @parser.split("#frag")
    )
  end

  def test_split_empty_relative_reference
    assert_equal(
      [nil, nil, nil, nil, nil, "", nil, nil, nil],
      @parser.split("")
    )
  end

  # --- parse: relative references become plain URI::Generic ---

  def test_parse_returns_generic_instance_for_relative_reference
    assert_instance_of(URI::Generic, @parser.parse("foo/bar"))
  end

  def test_parse_relative_reference_keeps_path
    assert_equal("foo/bar", @parser.parse("foo/bar").path)
  end

  # --- join: base URL resolution (delegates to Generic#merge) ---

  def test_join_resolves_relative_path_against_base
    result = @parser.join("http://example.com/a/b", "c")
    assert_equal("http://example.com/a/c", result.to_s)
  end

  def test_join_resolves_absolute_path_against_base
    result = @parser.join("http://example.com/a/b", "/c")
    assert_equal("http://example.com/c", result.to_s)
  end

  def test_join_resolves_network_path_reference_against_base
    result = @parser.join("http://example.com/a/b", "//example.org/c")
    assert_equal("http://example.org/c", result.to_s)
  end

  def test_join_resolves_query_only_reference_and_keeps_base_path
    result = @parser.join("http://example.com/a/b?x=1", "?y=2")
    assert_equal("http://example.com/a/b?y=2", result.to_s)
  end

  def test_join_resolves_fragment_only_reference_and_keeps_base_query
    result = @parser.join("http://example.com/a/b?x=1", "#frag")
    assert_equal("http://example.com/a/b?x=1#frag", result.to_s)
  end

  def test_join_resolves_dot_dot_segments_against_base
    result = @parser.join("http://example.com/a/b/c", "../d")
    assert_equal("http://example.com/a/d", result.to_s)
  end
end
