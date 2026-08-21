# frozen_string_literal: true
require "test/unit"
require "uri"
require "uri/whatwg_parser"

# URI::WHATWG_Parser#split must return the same 9-element contract as
# URI::RFC3986_Parser#split:
#
#   [scheme, userinfo, host, port, registry, path, opaque, query, fragment]
#
# so that URI.for(*parser.split(uri), parser) keeps working unmodified.
# registry is always nil. Only http/https get full structural parsing;
# any other scheme is a minimal opaque URI (see the "unsupported scheme"
# section below).
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

  # --- unsupported scheme (opaque) ---
  #
  # Only http/https get full structural parsing (authority, host, path
  # segmentation, IDNA, percent-encoding). Any other scheme is treated as
  # a minimal opaque URI (scheme + opaque part), matching how
  # RFC3986_Parser#split handles e.g. "mailto:foo@example.org" via its
  # path-rootless case. This keeps Generic#merge's "return rel if
  # rel.absolute?" step (RFC2396 5.2) working for relative references
  # whose first path segment contains a colon, e.g. resolving "foo:bar"
  # against a base URL: RFC3986 doesn't allow a colon in the first
  # segment of a relative-path reference, so it must be treated as an
  # absolute URI instead of erroring out.

  def test_split_treats_unsupported_scheme_as_opaque_uri
    assert_equal(
      ["foo", nil, nil, nil, nil, nil, "bar", nil, nil],
      @parser.split("foo:bar")
    )
  end

  def test_split_keeps_query_inside_opaque_part_for_unsupported_scheme
    result = @parser.split("mailto:foo@example.org?subject=hi")
    assert_equal("mailto", result[0])
    assert_equal("foo@example.org?subject=hi", result[6])
    assert_nil(result[7])
  end

  def test_split_returns_fragment_for_opaque_uri
    assert_equal("frag", @parser.split("foo:bar#frag")[8])
  end

  def test_parse_returns_generic_for_unsupported_scheme
    result = @parser.parse("foo:bar")
    assert_instance_of(URI::Generic, result)
    assert_equal("bar", result.opaque)
  end

  def test_join_resolves_opaque_absolute_uri_by_ignoring_base
    base = @parser.parse("http://example.com/a/b")
    result = @parser.join(base, "foo:bar")
    assert_equal("foo:bar", result.to_s)
  end

  # --- host & path ---

  def test_split_returns_host_for_simple_http_url
    assert_equal("example.com", @parser.split("http://example.com")[2])
  end

  # --- backslash as path separator (special scheme compatibility) ---
  #
  # WHATWG treats "\" the same as "/" within the authority and path of a
  # special scheme (http/https here), for compatibility with how browsers
  # tolerate it. This does not extend into the query string.

  def test_split_treats_backslash_as_path_separator
    assert_equal("/foo/bar", @parser.split("http://example.com/foo\\bar")[5])
  end

  def test_split_treats_backslash_authority_slashes
    result = @parser.split("http:\\\\example.com\\foo")
    assert_equal("example.com", result[2])
    assert_equal("/foo", result[5])
  end

  def test_split_treats_backslash_as_separator_in_relative_reference
    assert_equal("foo/bar", @parser.split("foo\\bar")[5])
  end

  def test_split_does_not_treat_backslash_in_query_as_separator
    assert_equal('a=b\c', @parser.split("http://example.com/foo?a=b\\c")[7])
  end

  def test_split_lowercases_uppercase_host
    assert_equal("example.com", @parser.split("http://EXAMPLE.COM")[2])
  end

  # --- IDNA (Punycode) host encoding ---

  def test_split_encodes_japanese_host_to_punycode
    assert_equal("xn--wgv71a119e.jp", @parser.split("http://日本語.jp/foo")[2])
  end

  def test_split_encodes_german_umlaut_host_to_punycode
    assert_equal("xn--mnchen-3ya.de", @parser.split("http://münchen.de/foo")[2])
  end

  def test_split_encodes_only_non_ascii_labels_in_mixed_host
    assert_equal("xn--wgv71a119e.example.com", @parser.split("http://日本語.example.com/foo")[2])
  end

  def test_split_lowercases_before_encoding_non_ascii_host
    assert_equal("xn--mnchen-3ya.de", @parser.split("http://MÜNCHEN.de/foo")[2])
  end

  def test_split_does_not_encode_ipv6_host_as_punycode
    assert_equal("[::1]", @parser.split("http://[::1]/foo")[2])
  end

  # --- forbidden host code points ---

  def test_split_raises_for_space_in_host
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://exa mple.com/foo")
    end
  end

  def test_split_raises_for_tab_in_host
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://exa\tmple.com/foo")
    end
  end

  def test_split_raises_for_angle_bracket_in_host
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://exa<mple.com/foo")
    end
  end

  def test_split_raises_for_square_bracket_in_unquoted_host
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://exa]mple.com/foo")
    end
  end

  def test_split_raises_for_pipe_in_host
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://exa|mple.com/foo")
    end
  end

  def test_split_raises_for_null_byte_in_host
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://exa\x00mple.com/foo")
    end
  end

  # --- missing host ---

  def test_split_raises_when_host_is_missing_with_no_path
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://")
    end
  end

  def test_split_allows_empty_host_in_relative_network_path_reference
    assert_equal("", @parser.split("///foo")[2])
  end

  # --- authority parsing ignores how many leading "/" follow the scheme ---
  #
  # For a known special scheme (http/https), WHATWG always tries to parse
  # an authority after the scheme, skipping any number (zero or more) of
  # leading "/" first -- not just the canonical "//". So
  # "http:///foo" has no missing host: the "///" is fully consumed and
  # "foo" is read as the host, leaving no path.

  def test_split_parses_authority_without_any_leading_slash
    result = @parser.split("http:example.com/foo")
    assert_equal("example.com", result[2])
    assert_equal("/foo", result[5])
  end

  def test_split_parses_authority_with_a_single_leading_slash
    result = @parser.split("http:/example.com/foo")
    assert_equal("example.com", result[2])
    assert_equal("/foo", result[5])
  end

  def test_split_parses_authority_after_extra_leading_slashes
    result = @parser.split("http:///foo")
    assert_equal("foo", result[2])
    assert_equal("/", result[5])
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

  # --- dot-segment normalization (absolute URLs only) ---

  def test_split_normalizes_single_dot_segment
    assert_equal("/a/b", @parser.split("http://example.com/a/./b")[5])
  end

  def test_split_normalizes_double_dot_segment
    assert_equal("/b", @parser.split("http://example.com/a/../b")[5])
  end

  def test_split_normalizes_trailing_single_dot_segment
    assert_equal("/a/b/", @parser.split("http://example.com/a/b/.")[5])
  end

  def test_split_normalizes_trailing_double_dot_segment
    assert_equal("/a/", @parser.split("http://example.com/a/b/..")[5])
  end

  def test_split_normalizes_double_dot_segment_beyond_root
    assert_equal("/a", @parser.split("http://example.com/../a")[5])
  end

  def test_split_normalizes_multiple_double_dot_segments
    assert_equal("/c", @parser.split("http://example.com/a/b/../../c")[5])
  end

  def test_split_normalizes_lone_double_dot_path
    assert_equal("/", @parser.split("http://example.com/..")[5])
  end

  def test_split_normalizes_lone_single_dot_path
    assert_equal("/", @parser.split("http://example.com/.")[5])
  end

  def test_split_normalizes_percent_encoded_single_dot_segment
    assert_equal("/a/b", @parser.split("http://example.com/a/%2e/b")[5])
  end

  def test_split_normalizes_percent_encoded_single_dot_segment_uppercase
    assert_equal("/a/b", @parser.split("http://example.com/a/%2E/b")[5])
  end

  def test_split_normalizes_percent_encoded_double_dot_segment
    assert_equal("/b", @parser.split("http://example.com/a/%2e%2e/b")[5])
  end

  def test_split_normalizes_mixed_literal_and_percent_encoded_double_dot_segment
    assert_equal("/b", @parser.split("http://example.com/a/.%2e/b")[5])
  end

  def test_split_does_not_normalize_dot_segments_in_relative_reference
    assert_equal("../foo", @parser.split("../foo")[5])
  end

  # --- IPv6 host ---

  def test_split_returns_bracketed_ipv6_host
    assert_equal("[::1]", @parser.split("http://[::1]/foo")[2])
  end

  def test_split_returns_nil_port_for_ipv6_host_without_port
    assert_nil(@parser.split("http://[::1]/foo")[3])
  end

  def test_split_returns_explicit_port_for_ipv6_host
    result = @parser.split("http://[::1]:8080/foo")
    assert_equal("[::1]", result[2])
    assert_equal("8080", result[3])
  end

  def test_split_normalizes_default_port_to_nil_for_ipv6_host
    assert_nil(@parser.split("http://[::1]:80/foo")[3])
  end

  def test_split_lowercases_ipv6_host
    assert_equal("[2001:db8::1]", @parser.split("http://[2001:DB8::1]/foo")[2])
  end

  def test_split_keeps_path_for_ipv6_host
    assert_equal("/foo/bar", @parser.split("http://[::1]/foo/bar")[5])
  end

  def test_split_normalizes_missing_path_to_root_for_ipv6_host
    assert_equal("/", @parser.split("http://[::1]")[5])
  end

  def test_split_compresses_fully_expanded_ipv6_host
    assert_equal("[::1]", @parser.split("http://[0:0:0:0:0:0:0:1]/foo")[2])
  end

  def test_split_compresses_ipv6_host_with_leading_zeros
    result = @parser.split("http://[2001:0db8:0000:0000:0000:0000:0000:0001]/foo")
    assert_equal("[2001:db8::1]", result[2])
  end

  def test_split_compresses_only_the_longest_zero_run_in_ipv6_host
    assert_equal("[0:0:1::1]", @parser.split("http://[0:0:1:0:0:0:0:1]/foo")[2])
  end

  def test_split_keeps_unspecified_ipv6_host_compressed
    assert_equal("[::]", @parser.split("http://[0:0:0:0:0:0:0:0]/foo")[2])
  end

  def test_split_raises_for_unclosed_ipv6_bracket
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://[::1/foo")
    end
  end

  def test_split_returns_nil_port_for_ipv6_host_with_trailing_colon
    assert_nil(@parser.split("http://[::1]:/foo")[3])
  end

  def test_split_raises_for_trailing_garbage_after_ipv6_bracket
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://[::1]x/foo")
    end
  end

  def test_split_raises_for_non_ipv6_text_in_brackets
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://[not-an-ipv6]/foo")
    end
  end

  def test_split_raises_for_ipv4_address_in_brackets
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://[1.2.3.4]/foo")
    end
  end

  def test_split_raises_for_ipv6_with_multiple_double_colons
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://[::1::2]/foo")
    end
  end

  def test_split_raises_for_empty_brackets
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://[]/foo")
    end
  end

  # --- IPv4 host ---

  def test_split_accepts_valid_ipv4_host
    assert_equal("1.2.3.4", @parser.split("http://1.2.3.4/foo")[2])
  end

  def test_split_accepts_ipv4_host_minimum_octet_boundary
    assert_equal("0.0.0.0", @parser.split("http://0.0.0.0/foo")[2])
  end

  def test_split_accepts_ipv4_host_maximum_octet_boundary
    assert_equal("255.255.255.255", @parser.split("http://255.255.255.255/foo")[2])
  end

  def test_split_raises_for_ipv4_octet_above_maximum_boundary
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://256.0.0.1/foo")
    end
  end

  def test_split_raises_for_wildly_out_of_range_ipv4_octets
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://999.999.999.999/foo")
    end
  end

  def test_split_raises_for_zero_padded_ipv4_octet
    assert_raise(URI::InvalidURIError) do
      @parser.split("http://01.02.03.04/foo")
    end
  end

  def test_split_does_not_treat_three_part_numeric_host_as_ipv4
    assert_equal("1.2.3", @parser.split("http://1.2.3/foo")[2])
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

  def test_split_returns_nil_port_for_trailing_colon_with_no_digits
    assert_nil(@parser.split("http://example.com:/foo")[3])
  end

  def test_split_returns_nil_port_for_trailing_colon_with_no_digits_and_no_path
    assert_nil(@parser.split("http://example.com:")[3])
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

  # --- authority boundary (host must not swallow query/path text) ---

  def test_split_stops_authority_at_query_delimiter_with_no_path
    result = @parser.split("http://example.com?foo=bar")
    assert_equal("example.com", result[2])
    assert_equal("foo=bar", result[7])
  end

  def test_split_does_not_treat_at_sign_in_query_as_userinfo_delimiter
    result = @parser.split("http://example.com/foo?a@b")
    assert_nil(result[1])
    assert_equal("example.com", result[2])
    assert_equal("a@b", result[7])
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

  # --- percent-encoding ---

  def test_split_percent_encodes_space_in_path
    assert_equal("/foo%20bar", @parser.split("http://example.com/foo bar")[5])
  end

  def test_split_percent_encodes_non_ascii_in_path
    assert_equal("/%E6%97%A5%E6%9C%AC%E8%AA%9E", @parser.split("http://example.com/日本語")[5])
  end

  def test_split_percent_encodes_double_quote_in_path
    assert_equal('/foo%22bar', @parser.split('http://example.com/foo"bar')[5])
  end

  def test_split_does_not_encode_unreserved_path_chars
    assert_equal("/foo-bar_baz.qux~1", @parser.split("http://example.com/foo-bar_baz.qux~1")[5])
  end

  def test_split_preserves_existing_percent_escape_in_path
    assert_equal("/foo%20bar", @parser.split("http://example.com/foo%20bar")[5])
  end

  def test_split_uppercases_existing_lowercase_percent_escape_in_path
    assert_equal("/foo%2Fbar", @parser.split("http://example.com/foo%2fbar")[5])
  end

  def test_split_uppercases_existing_lowercase_percent_escape_in_query
    assert_equal("a=%2F", @parser.split("http://example.com/foo?a=%2f")[7])
  end

  def test_split_encodes_lone_percent_sign_in_path
    assert_equal("/100%25off", @parser.split("http://example.com/100%off")[5])
  end

  def test_split_percent_encodes_non_ascii_in_query
    assert_equal("q=%E6%97%A5%E6%9C%AC%E8%AA%9E", @parser.split("http://example.com/foo?q=日本語")[7])
  end

  def test_split_percent_encodes_single_quote_in_query
    assert_equal("a=b%27c", @parser.split("http://example.com/foo?a=b'c")[7])
  end

  def test_split_percent_encodes_non_ascii_in_fragment
    assert_equal("%E6%97%A5%E6%9C%AC%E8%AA%9E", @parser.split("http://example.com/foo#日本語")[8])
  end

  def test_split_percent_encodes_double_quote_in_fragment
    assert_equal('foo%22bar', @parser.split('http://example.com/foo#foo"bar')[8])
  end

  def test_split_percent_encodes_backtick_in_fragment
    assert_equal("foo%60bar", @parser.split("http://example.com/foo#foo`bar")[8])
  end

  def test_split_percent_encodes_special_char_in_userinfo
    assert_equal("us%3Cer:pass", @parser.split("http://us<er:pass@example.com/")[1])
  end

  def test_split_percent_encodes_non_ascii_in_userinfo
    assert_equal("%E6%97%A5:pass", @parser.split("http://日:pass@example.com/")[1])
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
