# frozen_string_literal: true

require_relative 'common'

module URI
  # A parser for the WHATWG URL Standard (https://url.spec.whatwg.org/).
  #
  # Phase 1: limited to absolute http/https URLs. It does not yet implement
  # base URL resolution, IDNA/IPv6 host parsing, dot-segment path
  # normalization, or percent-encoding.
  class WHATWG_Parser # :nodoc:
    SPECIAL_SCHEME_DEFAULT_PORTS = {
      'http' => 80,
      'https' => 443,
    }.freeze

    SCHEME_PATTERN = /\A[A-Za-z][A-Za-z0-9+\-.]*\z/
    PORT_PATTERN = /\A\d+\z/
    MAX_PORT = 65535

    def parse(uri) # :nodoc:
      URI.for(*self.split(uri), self)
    end

    def join(*uris) # :nodoc:
      uris[0] = convert_to_uri(uris[0])
      uris.inject :merge
    end

    # Delegates character-set validation to URI::RFC3986_Parser, since Phase 1
    # only replaces URL structure parsing (#split), not component syntax.
    def regexp
      RFC3986_PARSER.regexp
    end

    # Returns [scheme, userinfo, host, port, registry, path, opaque, query, fragment],
    # matching the contract of URI::RFC3986_Parser#split. registry and opaque
    # are always nil, since Phase 1 only handles absolute http/https URLs.
    def split(input)
      before_fragment, fragment = parse_fragment(input)
      scheme, after_scheme = parse_scheme(before_fragment)
      authority = after_scheme.delete_prefix('//')
      username, password, host_port_path = parse_userinfo(authority)
      host_port, path_and_query = split_host_port_and_path(host_port_path)
      host, port = parse_host_port(host_port, scheme)
      path, query = parse_query(path_and_query)

      [scheme, join_userinfo(username, password), host, port, nil, path, nil, query, fragment]
    end

    private

    # fragment state: everything after the first "#" is the fragment.
    def parse_fragment(input)
      before, sep, fragment = input.partition('#')
      fragment = nil if sep.empty?
      [before, fragment]
    end

    # scheme start state / scheme state.
    def parse_scheme(before_fragment)
      scheme, sep, rest = before_fragment.partition(':')
      if sep.empty? || !SCHEME_PATTERN.match?(scheme)
        raise InvalidURIError, "bad URI (missing scheme): #{before_fragment}"
      end

      scheme = scheme.downcase
      unless SPECIAL_SCHEME_DEFAULT_PORTS.key?(scheme)
        raise InvalidURIError, "unsupported scheme: #{scheme}"
      end

      [scheme, rest]
    end

    # authority state: username ":" password "@" up to the last "@".
    def parse_userinfo(authority)
      userinfo_str, sep, host_port_path = authority.rpartition('@')
      return [nil, nil, authority] if sep.empty?

      username, colon, password = userinfo_str.partition(':')
      password = nil if colon.empty?
      [username, password, host_port_path]
    end

    def join_userinfo(username, password)
      return nil if username.nil?
      return username if password.nil?

      "#{username}:#{password}"
    end

    # splits authority-rest into "host:port" and a "/"-prefixed path+query,
    # normalizing a missing path to "/".
    def split_host_port_and_path(host_port_path)
      slash_index = host_port_path.index('/')
      if slash_index
        [host_port_path[0...slash_index], host_port_path[slash_index..-1]]
      else
        [host_port_path, '/']
      end
    end

    # host state / port state.
    def parse_host_port(host_port, scheme)
      host, port_str = host_port.split(':', 2)
      host = host.downcase
      if port_str.nil?
        port = nil
      else
        port_number = parse_port(port_str)
        port = port_number == SPECIAL_SCHEME_DEFAULT_PORTS[scheme] ? nil : port_str
      end
      [host, port]
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
