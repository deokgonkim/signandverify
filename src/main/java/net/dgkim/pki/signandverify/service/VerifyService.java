package net.dgkim.pki.signandverify.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import net.dgkim.pki.signandverify.exception.PKIException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

@Service
public class VerifyService {
    public boolean verifyMessage(byte[] msg, byte[] sign) throws CMSException, OperatorCreationException, CertificateException, PKIException {
        boolean verify = false;
        ASN1InputStream asn1InputStream = null;
        CMSSignedData signedData = null;
        
        asn1InputStream = new ASN1InputStream(sign);
        
        signedData = new CMSSignedData(new CMSProcessableByteArray(msg), asn1InputStream);
        
        Store certStore = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();
        
        Iterator<SignerInformation> it = signers.getSigners().iterator();
        
        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            
            Iterator<X509CertificateHolder> certIt = certStore.getMatches(signer.getSID()).iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
            
            //verify = signer.verify(new BcRSASignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider()).build(cert));
            verify = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(cert));
            
            verifyCertificate(cert);
            
            
        }
        
        return verify;
    }
    
    public void verifyCertificate(X509CertificateHolder certHolder) throws PKIException, CertificateException {
        //X509Certificate cert = new X509V2AttributeCertificate( attributeCertificateHolder.getEncoded() );
        X509Certificate cert = new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certHolder );
        try {
            if ( !certHolder.isValidOn(new Date()) ) {
                throw new PKIException("is not valid certificate");
            }
            
            List<String> crlDistPoints = getCrlDistributionPoints(cert);
            for (String crlDP : crlDistPoints) {
                X509CRL crl = downloadCRL(crlDP);
                if (crl.isRevoked(cert)) {
                    throw new PKIException("The certificate is revoked by CRL: " + crlDP);
                }
            }
        } catch (IOException e) {
            throw new PKIException(e);
        } catch (CertificateParsingException e) {
            throw new PKIException(e);
        } catch (CertificateException e) {
            throw new PKIException(e);
        } catch (CRLException e) {
            throw new PKIException(e);
        } catch (NamingException e) {
            throw new PKIException(e);
        }
    }
    
    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
     * extension in a X.509 certificate. If CRL distribution point extension is
     * unavailable, returns an empty list. 
     */
    public static List<String> getCrlDistributionPoints(X509Certificate cert) throws CertificateParsingException, IOException {
        byte[] crldpExt = cert.getExtensionValue(X509Extension.cRLDistributionPoints.getId());
        if (crldpExt == null) {
            List<String> emptyList = new ArrayList<String>();
            return emptyList;
        }
        ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crldpExt));
        DEROctetString dosCrlDP = (DEROctetString) oAsnInStream.readObject();
        byte[] crldpExtOctets = dosCrlDP.getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
        CRLDistPoint distPoint = CRLDistPoint.getInstance(oAsnInStream2.readObject());
        List<String> crlUrls = new ArrayList<String>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null) {
                if (dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(
                        dpn.getName()).getNames();
                    // Look for an URI
                    for (int j = 0; j < genNames.length; j++) {
                        if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(
                                genNames[j].getName()).getString();
                            crlUrls.add(url);
                        }
                    }
                }
            }
        }
        return crlUrls;
    }
    
    /**
     * Downloads CRL from given URL. Supports http, https, ftp and ldap based URLs.
     */
    private static X509CRL downloadCRL(String crlURL) throws IOException,
            CertificateException, CRLException, NamingException, PKIException {
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
                || crlURL.startsWith("ftp://")) {
            X509CRL crl = downloadCRLFromWeb(crlURL);
            return crl;
        } else if (crlURL.startsWith("ldap://")) {
            X509CRL crl = downloadCRLFromLDAP(crlURL);
            return crl;
        } else {
            throw new PKIException(
                    "Can not download CRL from certificate " +
                    "distribution point: " + crlURL);
        }
    }
    
    /**
     * Downloads a CRL from given LDAP url, e.g.
     * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     */
    private static X509CRL downloadCRLFromLDAP(String ldapURL) 
            throws CertificateException, NamingException, CRLException, PKIException {
        Hashtable<String , String> env = new Hashtable<String , String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, 
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext(env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[])aval.get();
        if ((val == null) || (val.length == 0)) {
            throw new PKIException(
                    "Can not download CRL from: " + ldapURL);
        } else {
            InputStream inStream = new ByteArrayInputStream(val);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL)cf.generateCRL(inStream);
            return crl;
        }
    }
    
    /**
     * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
     * http://crl.infonotary.com/crl/identity-ca.crl
     */
    private static X509CRL downloadCRLFromWeb(String crlURL)
            throws MalformedURLException, IOException, CertificateException,
            CRLException {
        URL url = new URL(crlURL);
        InputStream crlStream = url.openStream();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
            return crl;
        } finally {
            crlStream.close();
        }
    }
    
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }
}
