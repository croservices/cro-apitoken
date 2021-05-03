use Cro::APIToken::Manager;
use Cro::APIToken::Token;

role Cro::APIToken::Store {
    #| Store a new token in the database, with the specified expiration and
    #| metadata.
    method create-token(Str $token, DateTime $expiration, %metadata --> Nil)
    	{ ... }

    #| Resolve a token and return a Cro::APIToken::Token object. The manager is
    #| passed as this is required to construct a Cro::APIToken::Token. If there
    #| is a token in the database, return it, regardless of whether it has
    #| expired or been revoked. If there is no matching token, return Nil.
    method resolve-token(Cro::APIToken::Manager $manager, Str $token --> Cro::APIToken::Token) { ... }

    #| Find all matching tokens according to the passed properties. The metadata
    #| to search on should always be top-level keys and match by a direct
    #| comparison. The manager is passed as this is required to construct a
    #| Cro::APIToken::Token. The result is a Seq of Cro::APIToken::Token.
    method find-tokens(Cro::APIToken::Manager $manager, :%metadata,
                       Bool :$expired = False, Bool :$revoked --> Seq)
    	{ ... }

    #| Revokes a token by its value passed, if present, otherwise does nothing.
    method revoke-token(Str $token --> Nil) { ... }
}
