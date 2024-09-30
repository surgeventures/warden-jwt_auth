# frozen_string_literal: true

module Warden
  module JWTAuth
    module Errors
      # Error raised when trying to decode a token that has been revoked for an
      # user
      class RevokedToken < JWT::DecodeError
      end

      # Error raised when the user decoded from a token is nil
      class NilUser < JWT::DecodeError
      end

      # Error raised when trying to decode a token for an scope that doesn't
      # match the one encoded in the payload
      class WrongScope < JWT::DecodeError
      end

      # Error raised when trying to decode a token without scope claim and
      # no default_scope set
      class MissingScopeWithNoDefaultFallback < JWT::DecodeError
      end

      # Error raised when trying to decode a token with aud_header not being specified
      # and no valid_auds set
      class MissingAudHeaderWithNoFallback < JWT::DecodeError
      end

      # Error raised when trying to decode a token which `aud` claim does not
      # match with the expected one
      class WrongAud < JWT::DecodeError
      end
    end
  end
end
