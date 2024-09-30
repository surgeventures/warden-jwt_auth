# frozen_string_literal: true

require 'warden/jwt_auth/errors'

module Warden
  module JWTAuth
    # Layer above token decoding which directly decodes a user from a JWT
    class UserDecoder
      include JWTAuth::Import['revocation_strategies']

      attr_reader :helper

      def initialize(**args)
        super
        @helper = PayloadUserHelper
      end

      # Returns the user that is encoded in a JWT. The scope is used to choose
      # the user repository to which send `#find_for_jwt_authentication(sub)`
      # with decoded `sub` claim.
      #
      # @param token [String] a JWT
      # @param scope [Symbol] Warden scope
      # @param aud [String] Expected aud claim
      # @return [Interfaces::User] an user, whatever it is
      # @raise [Errors::RevokedToken] when token has been revoked for the
      # encoded user
      # @raise [Errors::NilUser] when decoded user is nil
      # @raise [Errors::WrongScope] when encoded scope does not match with scope
      # @raise [Errors::WrongAud] when encoded aud does not match with aud argument
      # rubocop:disable Metrics/MethodLength
      def call(token, scope, aud)
        config = JWTAuth.config
        payload = TokenDecoder.new.call(token)

        if payload_has_no_scope?(payload)
          unless config.default_scope
            raise Errors::MissingScopeWithNoDefaultFallback, 'payload has no scp claim and no default_scope is set'
          end

          scope = payload['scp'] = config.default_scope
        end

        check_valid_claims(payload, scope, aud)
        user = helper.find_user(payload)
        check_valid_user(payload, user, scope)
        user
      end
      # rubocop:enable Metrics/MethodLength

      private

      def check_valid_claims(payload, scope, aud)
        raise Errors::WrongScope, 'wrong scope' unless helper.scope_matches?(payload, scope)

        if aud.nil? && !payload['aud'].nil?
          check_empty_aud_header(payload)
        else
          raise Errors::WrongAud, 'wrong aud' unless helper.aud_matches?(payload, aud)
        end

        scope
      end

      def check_empty_aud_header(payload)
        unless JWTAuth.config.valid_auds
          raise Errors::MissingAudHeaderWithNoFallback, 'aud_header is missing and valid_auds setting is unset'
        end

        # rubocop:disable Style/GuardClause
        unless helper.aud_matches_valid_ones?(payload)
          raise Errors::WrongAud, 'aud_header missing and aud claim is not part of the valid_auds setting'
        end
        # rubocop:enable Style/GuardClause
      end

      def check_valid_user(payload, user, scope)
        raise Errors::NilUser, 'nil user' unless user

        strategy = revocation_strategies[scope.to_sym]
        raise Errors::RevokedToken, 'revoked token' if strategy.jwt_revoked?(payload, user)
      end

      def payload_has_no_scope?(payload)
        !payload.keys.member?('scp')
      end
    end
  end
end
