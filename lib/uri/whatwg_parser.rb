# frozen_string_literal: true

require 'ipaddr'
require_relative 'common'

module URI
  # A parser for the WHATWG URL Standard (https://url.spec.whatwg.org/).
  #
  # Limited to the http/https schemes. Percent-encoding is not implemented.
  # Non-ASCII domain labels are Punycode-encoded (RFC 3492), but the fuller
  # UTS #46 mapping/validation rules (case folding beyond ASCII, disallowed
  # code points, combining marks, etc.) are not.
  class WHATWG_Parser # :nodoc:
    # Punycode (RFC 3492): encodes a Unicode label's codepoints into the
    # ASCII string used after the "xn--" prefix in an IDNA domain label.
    module Punycode # :nodoc:
      BASE = 36
      TMIN = 1
      TMAX = 26
      SKEW = 38
      DAMP = 700
      INITIAL_BIAS = 72
      INITIAL_N = 128

      module_function

      def encode(codepoints)
        n = INITIAL_N
        delta = 0
        bias = INITIAL_BIAS
        output = +''

        basic = codepoints.select { |cp| cp < 0x80 }
        basic.each { |cp| output << cp.chr }
        h = b = basic.length

        output << '-' if b > 0

        while h < codepoints.length
          m = codepoints.select { |cp| cp >= n }.min
          delta += (m - n) * (h + 1)
          n = m

          codepoints.each do |c|
            delta += 1 if c < n
            next unless c == n

            q = delta
            k = BASE
            loop do
              t = if k <= bias
                    TMIN
                  elsif k >= bias + TMAX
                    TMAX
                  else
                    k - bias
                  end
              break if q < t

              output << encode_digit(t + (q - t) % (BASE - t))
              q = (q - t) / (BASE - t)
              k += BASE
            end
            output << encode_digit(q)
            bias = adapt(delta, h + 1, h == b)
            delta = 0
            h += 1
          end
          delta += 1
          n += 1
        end

        output
      end

      def encode_digit(d)
        (d + 22 + (d < 26 ? 75 : 0)).chr
      end

      def adapt(delta, numpoints, first_time)
        delta = first_time ? delta / DAMP : delta / 2
        delta += delta / numpoints
        k = 0
        while delta > ((BASE - TMIN) * TMAX) / 2
          delta /= (BASE - TMIN)
          k += BASE
        end
        k + (BASE - TMIN + 1) * delta / (delta + SKEW)
      end
    end

    SPECIAL_SCHEME_DEFAULT_PORTS = {
      'http' => 80,
      'https' => 443,
    }.freeze

    SCHEME_PATTERN = /\A[A-Za-z][A-Za-z0-9+\-.]*\z/
    PORT_PATTERN = /\A\d+\z/
    MAX_PORT = 65535
    IPV4_LIKE_PATTERN = /\A\d{1,3}(\.\d{1,3}){3}\z/

    # WHATWG forbidden host code points (https://url.spec.whatwg.org/#forbidden-host-code-point),
    # excluding "/", ":", "@", "#", "?", and "\", which never reach here:
    # they're already consumed by fragment/authority/backslash handling
    # before a host string is produced.
    FORBIDDEN_HOST_PATTERN = /[\x00\t\n\r <>\[\]^|]/

    # WHATWG percent-encode sets (https://url.spec.whatwg.org/#percent-encoded-bytes).
    # http/https are special schemes, so the query set below is the
    # "special-query" set (it includes "'").
    C0_CONTROL_PERCENT_ENCODE_SET = (0x00..0x1F).to_a.freeze
    FRAGMENT_PERCENT_ENCODE_SET = (C0_CONTROL_PERCENT_ENCODE_SET + ' "<>`'.bytes).freeze
    QUERY_PERCENT_ENCODE_SET = (C0_CONTROL_PERCENT_ENCODE_SET + %q{ "#<>'}.bytes).freeze
    PATH_PERCENT_ENCODE_SET = (C0_CONTROL_PERCENT_ENCODE_SET + %q{ "#<>?^`{}}.bytes).freeze
    USERINFO_PERCENT_ENCODE_SET = (PATH_PERCENT_ENCODE_SET + '/:;=@[\]|'.bytes).freeze

    # The full #percent_encode gsub pattern for encode_set: an existing
    # "%XX" escape, or one or more consecutive ASCII bytes NOT in
    # encode_set (0x21-0x7E only; 0x20 and below/0x7F+ are always
    # unsafe; "%" (0x25) is excluded even though no encode_set lists it,
    # so an existing escape or a lone "%" is always seen on its own), or
    # (falling through to ".") a single byte that needs encoding.
    # Built once per encode_set and frozen as a constant below --
    # interpolating a sub-pattern into a regexp literal on every call
    # would recompile it every time, which measurably matters here since
    # #percent_encode runs on every #split call.
    def self.percent_encode_pattern(encode_set)
      safe_bytes = (0x21..0x7E).reject { |b| encode_set.include?(b) || b == 0x25 }
      safe_run = safe_bytes.map { |b| Regexp.escape(b.chr) }.join
      Regexp.new("%[0-9A-Fa-f]{2}|[#{safe_run}]+|.", Regexp::MULTILINE)
    end
    private_class_method :percent_encode_pattern

    FRAGMENT_ENCODE_PATTERN = percent_encode_pattern(FRAGMENT_PERCENT_ENCODE_SET).freeze
    QUERY_ENCODE_PATTERN = percent_encode_pattern(QUERY_PERCENT_ENCODE_SET).freeze
    PATH_ENCODE_PATTERN = percent_encode_pattern(PATH_PERCENT_ENCODE_SET).freeze
    USERINFO_ENCODE_PATTERN = percent_encode_pattern(USERINFO_PERCENT_ENCODE_SET).freeze

    def parse(uri) # :nodoc:
      URI.for(*self.split(uri), self)
    end

    def join(*uris) # :nodoc:
      uris[0] = convert_to_uri(uris[0])
      uris.inject :merge
    end

    # Delegates character-set validation to URI::RFC3986_Parser: this parser
    # only replaces URL structure parsing (#split), not component syntax.
    def regexp
      RFC3986_PARSER.regexp
    end

    # Returns [scheme, userinfo, host, port, registry, path, opaque, query, fragment],
    # matching the contract of URI::RFC3986_Parser#split. registry is
    # always nil.
    #
    # An absolute http/https URL (with scheme) is parsed in full, with a
    # missing path normalized to "/". A scheme-less input is parsed as a
    # relative reference (network-path, absolute-path, relative-path, or
    # empty) with userinfo/host/port unset unless it is a network-path
    # reference ("//host/..."); its path is left as "" when missing, since
    # Generic#merge treats an empty rel.path as "no path given"
    # (RFC2396 5.2, step 2). Relative references are meant to be fed to
    # Generic#merge (via #parse / #join) to resolve against a base URL;
    # they are not resolvable on their own.
    #
    # A scheme other than http/https is treated as a minimal opaque URI
    # (see #parse_scheme): opaque holds everything after the scheme
    # (including any "?query"), and userinfo/host/port/path/query are nil.
    def split(input)
      before_fragment, fragment = parse_fragment(input)
      fragment = percent_encode(fragment, FRAGMENT_PERCENT_ENCODE_SET, FRAGMENT_ENCODE_PATTERN) if fragment
      scheme, rest = parse_scheme(before_fragment)

      if scheme && !SPECIAL_SCHEME_DEFAULT_PORTS.key?(scheme)
        return [scheme, nil, nil, nil, nil, nil, rest, nil, fragment]
      end

      rest = normalize_backslashes(rest)

      if rest.start_with?('//')
        authority, path_and_query = split_authority(rest.delete_prefix('//'))
        username, password, host_port = parse_userinfo(authority)
        empty_path_default = scheme ? '/' : ''
        path_and_query = empty_path_default if path_and_query.empty?
        host, port = parse_host_port(host_port, scheme)
        path, query = parse_query(path_and_query)
        path = percent_encode(path, PATH_PERCENT_ENCODE_SET, PATH_ENCODE_PATTERN)
        path = normalize_dot_segments(path) if scheme
        query = percent_encode(query, QUERY_PERCENT_ENCODE_SET, QUERY_ENCODE_PATTERN) if query
        username = percent_encode(username, USERINFO_PERCENT_ENCODE_SET, USERINFO_ENCODE_PATTERN) if username
        password = percent_encode(password, USERINFO_PERCENT_ENCODE_SET, USERINFO_ENCODE_PATTERN) if password
        userinfo = join_userinfo(username, password)
      else
        host = nil
        port = nil
        userinfo = nil
        path, query = parse_query(rest)
        path = percent_encode(path, PATH_PERCENT_ENCODE_SET, PATH_ENCODE_PATTERN)
        query = percent_encode(query, QUERY_PERCENT_ENCODE_SET, QUERY_ENCODE_PATTERN) if query
      end

      [scheme, userinfo, host, port, nil, path, nil, query, fragment]
    end

    private

    # fragment state: everything after the first "#" is the fragment.
    def parse_fragment(input)
      before, sep, fragment = input.partition('#')
      fragment = nil if sep.empty?
      [before, fragment]
    end

    # WHATWG treats "\" the same as "/" within the authority and path of
    # a special scheme (http/https here), for compatibility with how
    # browsers tolerate it. This does not extend into the query string,
    # so only the part before the first "?" is affected.
    def normalize_backslashes(rest)
      before_query, sep, query_part = rest.partition('?')
      before_query = before_query.tr('\\', '/')
      sep.empty? ? before_query : "#{before_query}?#{query_part}"
    end

    # scheme start state / scheme state. Returns [nil, before_fragment]
    # unchanged when no valid scheme prefix is present, so the caller can
    # fall back to relative-reference parsing. A recognized but
    # unsupported scheme (anything other than http/https) is still
    # returned here; #split treats it as an opaque URI.
    def parse_scheme(before_fragment)
      scheme, sep, rest = before_fragment.partition(':')
      return [nil, before_fragment] if sep.empty? || !SCHEME_PATTERN.match?(scheme)

      [scheme.downcase, rest]
    end

    # authority state: username ":" password "@" up to the last "@".
    def parse_userinfo(authority)
      userinfo_str, sep, host_port = authority.rpartition('@')
      return [nil, nil, authority] if sep.empty?

      username, colon, password = userinfo_str.partition(':')
      password = nil if colon.empty?
      [username, password, host_port]
    end

    def join_userinfo(username, password)
      return nil if username.nil?
      return username if password.nil?

      "#{username}:#{password}"
    end

    # UTF-8 percent-encodes each character in encode_set, plus any
    # character above U+007E (per the WHATWG C0 control percent-encode
    # set). An existing "%XX" escape is preserved but uppercased (WHATWG
    # always emits uppercase hex digits); a lone "%" not followed by two
    # hex digits is encoded to "%25" rather than left bare, since
    # Generic#query=/#fragment= raise on an invalid escape.
    #
    # pattern is this encode_set's precomputed #self.percent_encode_pattern
    # (e.g. PATH_ENCODE_PATTERN), which lets gsub consume a whole run of
    # encode_set-free ASCII bytes in a single match/block call, instead
    # of invoking the block once per character -- the common case for
    # real-world URLs, where most of a component's bytes need no
    # encoding at all.
    def percent_encode(str, encode_set, pattern)
      str.gsub(pattern) do |match|
        if match.length == 3 && match.start_with?('%')
          match.upcase
        elsif match.length > 1
          match
        elsif match == '%'
          '%25'
        elsif match.ord > 0x7E || encode_set.include?(match.ord)
          match.bytes.map { |b| format('%%%02X', b) }.join
        else
          match
        end
      end
    end

    # Splits "authority-and-rest" (everything after the "//") into the
    # authority ("userinfo@host:port") and a path+query, which end at the
    # first "/" or "?" -- whichever comes first. Neither may appear
    # inside the authority: an early "?" (e.g. "example.com?q=1", no
    # path) must not be swallowed into the host, and an "@" inside the
    # path/query must not be mistaken for the userinfo delimiter.
    def split_authority(authority_and_rest)
      end_index = authority_and_rest.index(/[\/?]/)
      if end_index
        [authority_and_rest[0...end_index], authority_and_rest[end_index..-1]]
      else
        [authority_and_rest, '']
      end
    end

    # host state / port state. A trailing ":" with no digits after it
    # (e.g. "example.com:") means the port was omitted, not that it's
    # invalid. An empty host (e.g. "http:///foo") is only an error for a
    # known special scheme (http/https); a scheme-less relative
    # network-path reference (e.g. "///foo") allows it, since whether
    # it's actually invalid depends on the base URL's scheme, which
    # #split doesn't have access to.
    def parse_host_port(host_port, scheme)
      host, port_str = split_host_and_port(host_port)
      host = normalize_domain(host) unless host.start_with?('[')
      if host.empty? && SPECIAL_SCHEME_DEFAULT_PORTS.key?(scheme)
        raise InvalidURIError, "host is missing"
      end
      if port_str.nil? || port_str.empty?
        port = nil
      else
        port_number = parse_port(port_str)
        port = port_number == SPECIAL_SCHEME_DEFAULT_PORTS[scheme] ? nil : port_str
      end
      [host, port]
    end

    # A "[...]"-bracketed IPv6 address may itself contain colons, so it
    # must be kept together instead of splitting host:port on the first
    # colon. Guards the empty-string case explicitly, since
    # "".split(':', 2) is [], not ['', nil].
    def split_host_and_port(host_port)
      return ['', nil] if host_port.empty?
      return host_port.split(':', 2) unless host_port.start_with?('[')

      close_bracket_index = host_port.index(']')
      unless close_bracket_index
        raise InvalidURIError, "invalid IPv6 address: #{host_port}"
      end

      address = normalize_ipv6_address(host_port[1...close_bracket_index])
      host = "[#{address}]"
      case host_port[(close_bracket_index + 1)..-1]
      when ''
        [host, nil]
      when /\A:(\d*)\z/
        [host, $1]
      else
        raise InvalidURIError, "invalid host: #{host_port}"
      end
    end

    # Lowercases each dot-separated label, Punycode-encoding (with an
    # "xn--" prefix) any label that isn't plain ASCII. A host with exactly
    # four dot-separated all-digit labels is validated as IPv4 instead;
    # WHATWG's fuller IPv4 grammar (octal/hex octets, fewer than four
    # parts) is not implemented, so e.g. "1.2.3" is treated as an ordinary
    # (non-IPv4) domain rather than rejected or expanded.
    def normalize_domain(host)
      raise InvalidURIError, "invalid host: #{host}" if FORBIDDEN_HOST_PATTERN.match?(host)
      return normalize_ipv4_address(host) if IPV4_LIKE_PATTERN.match?(host)

      host.split('.', -1).map { |label| normalize_label(label) }.join('.')
    end

    def normalize_label(label)
      label = label.downcase
      return label if label.ascii_only?

      "xn--#{Punycode.encode(label.codepoints)}"
    end

    # Validates the address via IPAddr and normalizes it to RFC 5952
    # compressed form, e.g. "0:0:0:0:0:0:0:1" -> "::1".
    def normalize_ipv6_address(address)
      ip = IPAddr.new(address)
      raise InvalidURIError, "invalid IPv6 address: #{address}" unless ip.ipv6?

      ip.to_s
    rescue IPAddr::Error
      raise InvalidURIError, "invalid IPv6 address: #{address}"
    end

    # Validates the address via IPAddr. Rejects an octet above 255 (e.g.
    # "256.0.0.1") and a zero-padded octet (e.g. "01.2.3.4"), since IPAddr
    # treats a leading zero as ambiguous rather than as octal.
    def normalize_ipv4_address(address)
      ip = IPAddr.new(address)
      raise InvalidURIError, "invalid IPv4 address: #{address}" unless ip.ipv4?

      ip.to_s
    rescue IPAddr::Error
      raise InvalidURIError, "invalid IPv4 address: #{address}"
    end

    def parse_port(port_str)
      unless PORT_PATTERN.match?(port_str)
        raise InvalidURIError, "bad port number: #{port_str}"
      end

      port = Integer(port_str)
      if port > MAX_PORT
        raise InvalidURIError, "port number out of range: #{port_str}"
      end

      port
    end

    # A segment counts as a single/double dot segment whether written
    # literally or percent-encoded (in either case), e.g. "%2e" and "%2E"
    # both count as ".", so ".%2e" counts as "..".
    SINGLE_DOT_SEGMENT_PATTERN = /\A(?:\.|%2e)\z/i
    DOUBLE_DOT_SEGMENT_PATTERN = /\A(?:\.|%2e){2}\z/i

    # path state: resolves "." and ".." segments within a single absolute
    # path, e.g. "/a/../b" -> "/b". A ".."  with no preceding segment left
    # to cancel is simply dropped (can't go above the root). A trailing "."
    # or ".." leaves a trailing slash, matching WHATWG path shortening.
    def normalize_dot_segments(path)
      segments = path.split('/', -1)
      segments.shift # the leading "" before the path's first "/"

      normalized = []
      segments.each_with_index do |segment, index|
        last = index == segments.size - 1
        if DOUBLE_DOT_SEGMENT_PATTERN.match?(segment)
          normalized.pop
          normalized << '' if last
        elsif SINGLE_DOT_SEGMENT_PATTERN.match?(segment)
          normalized << '' if last
        else
          normalized << segment
        end
      end

      "/#{normalized.join('/')}"
    end

    # query state: everything after the first "?" (before any fragment).
    def parse_query(path_and_query)
      path, sep, query = path_and_query.partition('?')
      query = nil if sep.empty?
      [path, query]
    end

    def convert_to_uri(uri)
      if uri.is_a?(URI::Generic)
        uri
      elsif uri = String.try_convert(uri)
        parse(uri)
      else
        raise ArgumentError,
          "bad argument (expected URI object or URI string)"
      end
    end
  end
end
