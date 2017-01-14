package net.dgkim.pki.signandverify.exception;

public class PKIException extends Exception {
    /**
     * 
     */
    private static final long serialVersionUID = 4170429082550130355L;

    public PKIException(Throwable e) {
        super(e);
    }
    
    public PKIException(String e) {
        super(e);
    }
}
