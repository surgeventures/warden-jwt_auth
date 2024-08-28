module Warden
  module JWTAuth
    class JWKS

      JWKS_CACHE_KEY = "auth/jwks-json".freeze

      def initialize(url)
        @jwks_url = url
      end

      def loader(options={})
        jwks(force: options[:invalidate]) || {}
      end

      def algo(key_index=0)
        loader[:keys][key_index][:alg]
      end

      private

      def fetch_jwks
        response = Faraday.get(@jwks_url)
        if response.status == 200
          JSON.parse(response.body.to_s)
        end
      end

      def jwks(force: false)
        Rails.cache.fetch(JWKS_CACHE_KEY, force: force, skip_nil: true) do
          fetch_jwks
        end&.deep_symbolize_keys
      end
    end
  end
end