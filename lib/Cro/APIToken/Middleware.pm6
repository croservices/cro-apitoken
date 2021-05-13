use Cro::APIToken::Manager;
use Cro::APIToken::Token;
use Cro::HTTP::Request;
use Cro::HTTP::Router;
use Cro::HTTP::Message;
use Cro::HTTP::Middleware;

#| Applications wanting to control (or restrict) access to their API based upon API tokens should implement this role.
#| It in turn acts as a piece of Cro HTTP middleware, and so can be installed in the usual ways (for example, with before).
#| The role has a single required attribute of type `Cro::APIToken::Manager` - that is, it must be constructed with
#| an API token manager, which in turn is constructed with a store.
#| By default, the middleware behaves as follows:
#|  - Looks for the API token to be provided using Bearer authorization (that is, in a header like `Authorization: Bearer <token>`).
#|  - If there is a valid token (non-expired, not-revoked) available, allows the request to proceed
#|  - Otherwise, produce a HTTP 401 Authorization Required response
#| All of these behaviors may be customized by overriding methods of the role.
role Cro::APIToken::Middleware does Cro::HTTP::Middleware::Conditional {
    has Cro::APIToken::Manager $.manager is required;

    method process(::?CLASS:D: Supply $requests) {
        supply whenever $requests -> $req {
            my $token-str = self.extract-token($req);
            my $token = $token-str ?? $!manager.resolve-token($token-str, :invalid) !! Cro::APIToken::Token;
            with $token {
                emit $_ ?? self.on-valid($req, $_) !! self.on-invalid($req, $_);
            } else {
                emit self.on-invalid($req, Cro::APIToken::Token);
            }
        }
    }

    #| Takes a HTTP request and extracts the token from it, returning it as a `Str`.
    #| The default implementation looks for an `Authorization` header using the Bearer authorization method.
    #| Override it to look for the API key in a difference place. If there is no such token, then returns `Nil`.
    method extract-token(Cro::HTTP::Request $request --> Str) {
        with $request.header('Authorization') {
            my $bearer-bits = $_.split(' ');
            return $bearer-bits[1] if $bearer-bits.elems == 2 && $bearer-bits[0] eq 'Bearer';
        }
        Nil;
    }

    #| When there is a valid API token, this method is called. The default implementation returns request.
    #| This is the place to extract information from the token and update the request's auth property using metadata
    #| from the token.
    method on-valid(Cro::HTTP::Request $request, Cro::APIToken::Token $token --> Cro::HTTP::Message) {
        $request;
    }

    #| Called when the API token is invalid. The default implementation returns a 401 response, however you may decide
    #| to do otherwise. The $token parameter may be undefined (a type object), in which case the API token simply
    #| didn't exist. In the case that the token was expired or revoked, then an instance of the token will be
    #| passed, and can be inspected (for example, if you want to provide some kind of diagnostics about that
    #| in the response, or at least to log it). If you have an API where you are willing to grant unauthorized access,
    #| but with some limited amount of functionality, then it is possible to return the request object instead,
    #| optionally setting `request.auth` up to model an anonymous user.
    method on-invalid(Cro::HTTP::Request $request, Cro::APIToken::Token $token --> Cro::HTTP::Message) {
        given Cro::HTTP::Response.new(:$request) {
            .status = 401;
            return $_;
        }
    }
}
