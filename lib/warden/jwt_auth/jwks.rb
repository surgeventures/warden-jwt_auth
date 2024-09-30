# frozen_string_literal: true

module Warden
  module JWTAuth
    # JWKS fetcher class.
    #
    # Uses a Rails cache key to store the payload
    class JWKS
      JWKS_CACHE_KEY = 'auth/jwks-json'

      def initialize(url)
        @jwks_url = url
      end

      def loader(options = {})
        jwks(force: options[:invalidate]) || {}
      end

      def algo(key_index = 0)
        loader[:keys][key_index][:alg]
      end

      private

      def fetch_jwks
        response = Faraday.get(@jwks_url)
        JSON.parse(response.body.to_s) if response.status == 200
      end

      def jwks(force: false)
        Rails.cache.fetch(JWKS_CACHE_KEY, force: force, skip_nil: true) do
          fetch_jwks
        end&.deep_symbolize_keys
      end
    end
  end
end
