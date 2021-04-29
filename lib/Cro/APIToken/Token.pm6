class Cro::APIToken::Token {
    has Str $.token;
    has %.metadata;
    has DateTime $.expiration;
    has Bool $.revoked = False;

    method expired(--> Bool) {
        DateTime.now > $!expiration;
    }

    method revoke(--> Nil) {
        $!revoked = True;
    }

    method Bool {
        not (self.expired or $!revoked);
    }
}
