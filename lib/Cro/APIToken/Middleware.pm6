use Cro::APIToken::Manager;
use Cro::APIToken::Token;
use Cro::HTTP::Request;
use Cro::HTTP::Router;
use Cro::HTTP::Message;
use Cro::HTTP::Middleware;

role Cro::APIToken::Middleware does Cro::HTTP::Middleware::Conditional {
    has Cro::APIToken::Manager $.manager is required;

    method process(Supply $requests) {
        die self.^name() ~ " cannot be used uninitialized, forgot to call `.new`?" unless self;

        supply whenever $requests -> $req {
            my $token-str = self.extract-token($req);
            my $token = $token-str ?? $!manager.resolve-token($token-str, :invalid) !! Cro::APIToken::Token;
            with $token {
                emit $_ ?? self.on-valid($req, $_) !! self.on-invalid($req, $_);
            } else {
                emit self.on-invalid($req, $token);
            }
        }
    }

    method extract-token(Cro::HTTP::Request $request --> Str) {
        with $request.header('Authorization') {
            my $bearer-bits = $_.split(' ');
            return $bearer-bits[1] if $bearer-bits.elems == 2 && $bearer-bits[0] eq 'Bearer';
        }
        Nil;
    }

    method on-valid(Cro::HTTP::Request $request, Cro::APIToken::Token $token --> Cro::HTTP::Message) {
        $request;
    }

    method on-invalid(Cro::HTTP::Request $request, Cro::APIToken::Token $token --> Cro::HTTP::Message) {
        given Cro::HTTP::Response.new(:$request) {
            .status = 401;
            return $_;
        }
    }
}
