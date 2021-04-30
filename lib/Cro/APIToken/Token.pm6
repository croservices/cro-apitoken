class Cro::APIToken::Token {
    has $.manager;
    has Str $.token;
    has %.metadata;
    has DateTime $.expiration;
    has Bool $.revoked = False;

    method expired(--> Bool) {
        DateTime.now > $!expiration;
    }

    method revoke(--> Nil) {
        $!manager.revoke($!token);
        $!revoked = True;
    }

    method Bool {
        not (self.expired or $!revoked);
    }
}
