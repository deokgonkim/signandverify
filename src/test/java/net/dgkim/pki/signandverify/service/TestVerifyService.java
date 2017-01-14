package net.dgkim.pki.signandverify.service;

import static org.junit.Assert.*;

import java.security.cert.CertificateException;

import net.dgkim.pki.signandverify.exception.PKIException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:app-config.xml" })
public class TestVerifyService {

    @Test
    public void test() {
        byte[] msg = null;
        byte[] sign = null;
        boolean result = false;
        
        msg = "a".getBytes();
        sign = signedA.getBytes();
        try {
            result = service.verifyMessage(msg, Base64.decode(signedA.getBytes()));
        } catch (CMSException e) {
            fail(e.getMessage());
        } catch (OperatorCreationException e) {
            fail(e.getMessage());
        } catch (CertificateException e) {
            fail(e.getMessage());
        } catch (PKIException e) {
            fail(e.getMessage());
        }
        assertTrue(result);
    }
    
    @Test
    public void testRevoked() {
        byte[] msg = null;
        byte[] sign = null;
        boolean result = false;
        
        msg = "a".getBytes();
        sign = signedArevoked.getBytes();
        try {
            result = service.verifyMessage(msg, Base64.decode(signedArevoked.getBytes()));
        } catch (CMSException e) {
            fail(e.getMessage());
        } catch (OperatorCreationException e) {
            fail(e.getMessage());
        } catch (CertificateException e) {
            fail(e.getMessage());
        } catch (PKIException e) {
            fail(e.getMessage());
        }
        assertTrue(result);
    }
    
    @Autowired
    public void setService(VerifyService service) {
        this.service = service;
    }
    
    private VerifyService service = null;
    
    private static final String signedA = 
            "MIIPBwYJKoZIhvcNAQcCoIIO+DCCDvQCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3"+
            "DQEHAaCCDFYwggVgMIIESKADAgECAhBpdu7ZEqtHe9bA3yCqSOsWMA0GCSqGSIb3"+
            "DQEBBQUAMIHdMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4x"+
            "HzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOzA5BgNVBAsTMlRlcm1z"+
            "IG9mIHVzZSBhdCBodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhIChjKTA5MR4w"+
            "HAYDVQQLExVQZXJzb25hIE5vdCBWYWxpZGF0ZWQxNzA1BgNVBAMTLlZlcmlTaWdu"+
            "IENsYXNzIDEgSW5kaXZpZHVhbCBTdWJzY3JpYmVyIENBIC0gRzMwHhcNMTIxMTA2"+
            "MDAwMDAwWhcNMTMxMTA4MjM1OTU5WjCCAQ0xFzAVBgNVBAoTDlZlcmlTaWduLCBJ"+
            "bmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMUYwRAYDVQQLEz13"+
            "d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvUlBBIEluY29ycC4gYnkgUmVmLixM"+
            "SUFCLkxURChjKTk4MR4wHAYDVQQLExVQZXJzb25hIE5vdCBWYWxpZGF0ZWQxMzAx"+
            "BgNVBAsTKkRpZ2l0YWwgSUQgQ2xhc3MgMSAtIE5ldHNjYXBlIEZ1bGwgU2Vydmlj"+
            "ZTEUMBIGA1UEAxQLRGVvZ0dvbiBLaW0xHjAcBgkqhkiG9w0BCQEWD2Rna2ltQGRn"+
            "a2ltLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMG6GmPx4ccZ"+
            "Ubetij0ajHVk9r/KjUEwJKJcfOolGlWpudfju3RpWlrYC9xbNmE/JR9GFabDVnsS"+
            "pb+trw1rp6dSdJPpbK8RpYhltu7oNAkiYOhJmlrmg3JETeY8jJtf2hEdweYRAqeZ"+
            "+rpNkjLzhr6MGkn7oTxjdFQnVHApiKTF+CGuwUZ4USQx7iapuX/20+1z8YApv6Rp"+
            "MIpGezVppUn1XiuPzLa8iNPzYbRjWXm0fC+v9LJSv4RBz49vj39ihLZYpwsTHTbw"+
            "GfTgGqhs+RaV1UeS7HffEGsUrfIUE64DovXjmdjx4fZNaVtyGw+ObdI27DczERsJ"+
            "gdYqUZQugwsCAwEAAaOB6DCB5TAJBgNVHRMEAjAAMEQGA1UdIAQ9MDswOQYLYIZI"+
            "AYb4RQEHFwEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cudmVyaXNpZ24uY29t"+
            "L3JwYTALBgNVHQ8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCsGAQUFBwMC"+
            "MBQGCmCGSAGG+EUBBgcEBhYETm9uZTBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8v"+
            "aW5kYzFkaWdpdGFsaWQtZzMtY3JsLnZlcmlzaWduLmNvbS9JbmRDMURpZ2l0YWxJ"+
            "RC1HMy5jcmwwDQYJKoZIhvcNAQEFBQADggEBAKHIdyVJjdAiRwCEekI2YZH/Enu/"+
            "aF/poVD/WDdOJNW01FpNLBaKmfqb39zSfq2w1BUo9N+r02KQEXQ5DuNmVDGFYvvw"+
            "Gi8P1vzcDE4nlD8JJ7oZYX4Yq9b0PDzVbyvKiNNfO+Xm5SAwnKeApoVRmdqXwurl"+
            "dm2FuCGgaXVK7YyYA3GDDf19Cz6eSzf5o7yw6ZUpITq+P8MYCrgnNN4WZRX5hzc/"+
            "+i6k0YZO1Uoprt/BONdbZgD1tfDUazapVwmAy26+HlDPYNZOP2BYsKLqqHdCG/ul"+
            "rXu3f5tHtmUvS7kwJxJJSIKafijzgJ7rEZ3eODuN7dOhC4GYTmxmzGegcOkwggbu"+
            "MIIF1qADAgECAhBxFWYFSuSRIU3pvET5rNPcMA0GCSqGSIb3DQEBBQUAMIHKMQsw"+
            "CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZl"+
            "cmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAxOTk5IFZlcmlTaWdu"+
            "LCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlT"+
            "aWduIENsYXNzIDEgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3Jp"+
            "dHkgLSBHMzAeFw0wOTA1MDEwMDAwMDBaFw0xOTA0MzAyMzU5NTlaMIHdMQswCQYD"+
            "VQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlT"+
            "aWduIFRydXN0IE5ldHdvcmsxOzA5BgNVBAsTMlRlcm1zIG9mIHVzZSBhdCBodHRw"+
            "czovL3d3dy52ZXJpc2lnbi5jb20vcnBhIChjKTA5MR4wHAYDVQQLExVQZXJzb25h"+
            "IE5vdCBWYWxpZGF0ZWQxNzA1BgNVBAMTLlZlcmlTaWduIENsYXNzIDEgSW5kaXZp"+
            "ZHVhbCBTdWJzY3JpYmVyIENBIC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw"+
            "ggEKAoIBAQDtxEffKigdfAZru9chMslsE4/psY1BTjT32gvjavpliCALERPpm+BJ"+
            "Totv1QHQXw1HkYpaTHQ+P8aRCbtMNJ6NbqGCUWL3aXZYlgevnhQYB09avZ/SMbJU"+
            "GXNGahlCEewScyGN9dwwzeXZVgoxxTZtKRSXvS3aiUcZiNhLBD3rtjxnHnQAEw3Q"+
            "htqTZ/gzA64aPGtpePbALI7hgz93+Zn//p9SWsK0hwrYbKlHwVQpZUM+SsCWH8Gt"+
            "93evbLEEXr7BtpQtl5AtJ9K7HumDaoT2xLKuIwZlJqUnWCsHIrRvpmJIGnfy1VAn"+
            "minTlvso9bokdmLjjFnr+27VQsS+Qcf1AgMBAAGjggK5MIICtTA0BggrBgEFBQcB"+
            "AQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLnZlcmlzaWduLmNvbTASBgNV"+
            "HRMBAf8ECDAGAQH/AgEAMHAGA1UdIARpMGcwZQYLYIZIAYb4RQEHFwEwVjAoBggr"+
            "BgEFBQcCARYcaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL2NwczAqBggrBgEFBQcC"+
            "AjAeGhxodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhMDQGA1UdHwQtMCswKaAn"+
            "oCWGI2h0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTEtZzMuY3JsMA4GA1UdDwEB"+
            "/wQEAwIBBjBuBggrBgEFBQcBDARiMGChXqBcMFowWDBWFglpbWFnZS9naWYwITAf"+
            "MAcGBSsOAwIaBBRLa7kolgYMu9BSOJsprEsHiyEFGDAmFiRodHRwOi8vbG9nby52"+
            "ZXJpc2lnbi5jb20vdnNsb2dvMS5naWYwLgYDVR0RBCcwJaQjMCExHzAdBgNVBAMT"+
            "FlByaXZhdGVMYWJlbDQtMjA0OC0xMTgwHQYDVR0OBBYEFHlHYQhB/TgEokvntcz1"+
            "Q/ZJKxH4MIHxBgNVHSMEgekwgeahgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRcwFQYD"+
            "VQQKEw5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0"+
            "d29yazE6MDgGA1UECxMxKGMpIDE5OTkgVmVyaVNpZ24sIEluYy4gLSBGb3IgYXV0"+
            "aG9yaXplZCB1c2Ugb25seTFFMEMGA1UEAxM8VmVyaVNpZ24gQ2xhc3MgMSBQdWJs"+
            "aWMgUHJpbWFyeSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEczghEAi1t1VoRU"+
            "hQsAz684SM6xpDANBgkqhkiG9w0BAQUFAAOCAQEAOU3PQZmBtakFtVI46TmEiWzk"+
            "NKha59hsCUwkGrpZpIc7cyHxk4HPv2hjWmf+NYUrocNdo0rCOhndMNbMTe/x0oGX"+
            "ylRaQ783i3qOGY0PQ6iM8q9gsxWKs5WcPOCesyeYpDVyF+X8Kl2H04oNwtFFKvjA"+
            "9KwqkzrVrhJwCOv7O+J37OgrZDV2zbra4NHLFNZxWJu+1T59ttnoJMUkZkxdkR92"+
            "sxc+fw3GIYkvsze4of9csm1J3mVSQvsOiNLtSh2/S+P4zHL6SA5ljknI1viZmDu3"+
            "lD4xcQaH+mxZUy7X3yvtX2MArBXtA7hVFozGaAPnIqhzC7G8oNpSWN0KDn/BgjGC"+
            "AnkwggJ1AgEBMIHyMIHdMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24s"+
            "IEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOzA5BgNVBAsT"+
            "MlRlcm1zIG9mIHVzZSBhdCBodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhIChj"+
            "KTA5MR4wHAYDVQQLExVQZXJzb25hIE5vdCBWYWxpZGF0ZWQxNzA1BgNVBAMTLlZl"+
            "cmlTaWduIENsYXNzIDEgSW5kaXZpZHVhbCBTdWJzY3JpYmVyIENBIC0gRzMCEGl2"+
            "7tkSq0d71sDfIKpI6xYwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG"+
            "9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTEyMTExNzEwNTgxNlowIwYJKoZIhvcNAQkE"+
            "MRYEFIb35Df6paf84V0d3Lnq6uo3dme4MA0GCSqGSIb3DQEBAQUABIIBAKsDnpaS"+
            "qfTK4ZinJ+X6+NKqc08tBged19YF6ORq9OmYbJzAcW4jp/awRMrPy5JMkivaeJ8M"+
            "Y0Dm2jkUByM68uld6oLIizgjCgRKnLKQf22kBusTm4jV5mc5uccsUtoMJkZeqlDg"+
            "p+aewLu+gj/+7IgMtchSkA4i8PdlkmBtF+em+D92FPqh/adlKui3kJmpVwVrp0Z+"+
            "bQNOsn2prjYmVvabLTnCJeMfcUmOav9Q1TrHd0NR3nvEYsoX1i9aBx47TAEihUsj"+
            "53BigPkiLK0tJsO57TWJS7J3vIx7tH3DGpgAJmFsX74v4sS7ENjV+esDhEGsHxD3"+
            "ikNviEP8A7r7MlY=";
    
    private String signedArevoked = "" +
            "MIIN7QYJKoZIhvcNAQcCoIIN3jCCDdoCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3"+
            "DQEHAaCCC70wggTHMIIDr6ADAgECAhAVrXP7MO9VL93zU9O32AmdMA0GCSqGSIb3"+
            "DQEBBQUAMIHdMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4x"+
            "HzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOzA5BgNVBAsTMlRlcm1z"+
            "IG9mIHVzZSBhdCBodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhIChjKTA5MR4w"+
            "HAYDVQQLExVQZXJzb25hIE5vdCBWYWxpZGF0ZWQxNzA1BgNVBAMTLlZlcmlTaWdu"+
            "IENsYXNzIDEgSW5kaXZpZHVhbCBTdWJzY3JpYmVyIENBIC0gRzMwHhcNMTExMTA5"+
            "MDAwMDAwWhcNMTIxMTA4MjM1OTU5WjCCAQ4xFzAVBgNVBAoTDlZlcmlTaWduLCBJ"+
            "bmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMUYwRAYDVQQLEz13"+
            "d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvUlBBIEluY29ycC4gYnkgUmVmLixM"+
            "SUFCLkxURChjKTk4MR4wHAYDVQQLExVQZXJzb25hIE5vdCBWYWxpZGF0ZWQxNDAy"+
            "BgNVBAsTK0RpZ2l0YWwgSUQgQ2xhc3MgMSAtIE1pY3Jvc29mdCBGdWxsIFNlcnZp"+
            "Y2UxFDASBgNVBAMUC0Rlb2dHb24gS2ltMR4wHAYJKoZIhvcNAQkBFg9kZ2tpbUBk"+
            "Z2tpbS5uZXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALK+uRo3D4zm162t"+
            "Bc5MBA3yfIdUT7hXcYPitaba2SAti83/2vFnqKM2VyaUjjmduqE5lRvOE09HHwvq"+
            "ZH8jMASfAcG70g2iDmrQZ7kVU3tk7Z7twDZqqr1uJO+rQALy2uHM0fWWNKiMyo3/"+
            "OgpXZWHnZ98JODUj9pawcQwn0rDhAgMBAAGjgdIwgc8wCQYDVR0TBAIwADBEBgNV"+
            "HSAEPTA7MDkGC2CGSAGG+EUBBxcBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3"+
            "LnZlcmlzaWduLmNvbS9ycGEwCwYDVR0PBAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUF"+
            "BwMEBggrBgEFBQcDAjBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vaW5kYzFkaWdp"+
            "dGFsaWQtZzMtY3JsLnZlcmlzaWduLmNvbS9JbmRDMURpZ2l0YWxJRC1HMy5jcmww"+
            "DQYJKoZIhvcNAQEFBQADggEBAISkuNWQ4mK+iJiRkBRkH/LMCMpWDMiUfEdM7F8m"+
            "vHSjWNbK99VgF1tE2SJYuNwbo82e11EDlKd+nj9jls78MZWS3kJ0WCcLKiqdOTEa"+
            "ENmxfjIAsX4k7rpyxpyHWHx3M9041iQVAIL5rle1BbLrg3R9HWDgzp5gCHGl23P8"+
            "QfkGkTznV5U6ZT2a4TYYdkYTJVfxUtzkxAz2OB55piDpng6m9+ay0innFdAMBWPA"+
            "uCWEJgS3NCdBElYlSN/8LPGoTWWbE1oFRF6N+0UzKm+G8on2unuuAl5IwluP1SJJ"+
            "zFDh+K8ExcB90JT1nY7tajNnc0EIunaDyIJLaTsUglJvUacwggbuMIIF1qADAgEC"+
            "AhBxFWYFSuSRIU3pvET5rNPcMA0GCSqGSIb3DQEBBQUAMIHKMQswCQYDVQQGEwJV"+
            "UzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRy"+
            "dXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAxOTk5IFZlcmlTaWduLCBJbmMuIC0g"+
            "Rm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNz"+
            "IDEgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHMzAe"+
            "Fw0wOTA1MDEwMDAwMDBaFw0xOTA0MzAyMzU5NTlaMIHdMQswCQYDVQQGEwJVUzEX"+
            "MBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0"+
            "IE5ldHdvcmsxOzA5BgNVBAsTMlRlcm1zIG9mIHVzZSBhdCBodHRwczovL3d3dy52"+
            "ZXJpc2lnbi5jb20vcnBhIChjKTA5MR4wHAYDVQQLExVQZXJzb25hIE5vdCBWYWxp"+
            "ZGF0ZWQxNzA1BgNVBAMTLlZlcmlTaWduIENsYXNzIDEgSW5kaXZpZHVhbCBTdWJz"+
            "Y3JpYmVyIENBIC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDt"+
            "xEffKigdfAZru9chMslsE4/psY1BTjT32gvjavpliCALERPpm+BJTotv1QHQXw1H"+
            "kYpaTHQ+P8aRCbtMNJ6NbqGCUWL3aXZYlgevnhQYB09avZ/SMbJUGXNGahlCEewS"+
            "cyGN9dwwzeXZVgoxxTZtKRSXvS3aiUcZiNhLBD3rtjxnHnQAEw3QhtqTZ/gzA64a"+
            "PGtpePbALI7hgz93+Zn//p9SWsK0hwrYbKlHwVQpZUM+SsCWH8Gt93evbLEEXr7B"+
            "tpQtl5AtJ9K7HumDaoT2xLKuIwZlJqUnWCsHIrRvpmJIGnfy1VAnminTlvso9bok"+
            "dmLjjFnr+27VQsS+Qcf1AgMBAAGjggK5MIICtTA0BggrBgEFBQcBAQQoMCYwJAYI"+
            "KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLnZlcmlzaWduLmNvbTASBgNVHRMBAf8ECDAG"+
            "AQH/AgEAMHAGA1UdIARpMGcwZQYLYIZIAYb4RQEHFwEwVjAoBggrBgEFBQcCARYc"+
            "aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL2NwczAqBggrBgEFBQcCAjAeGhxodHRw"+
            "czovL3d3dy52ZXJpc2lnbi5jb20vcnBhMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6"+
            "Ly9jcmwudmVyaXNpZ24uY29tL3BjYTEtZzMuY3JsMA4GA1UdDwEB/wQEAwIBBjBu"+
            "BggrBgEFBQcBDARiMGChXqBcMFowWDBWFglpbWFnZS9naWYwITAfMAcGBSsOAwIa"+
            "BBRLa7kolgYMu9BSOJsprEsHiyEFGDAmFiRodHRwOi8vbG9nby52ZXJpc2lnbi5j"+
            "b20vdnNsb2dvMS5naWYwLgYDVR0RBCcwJaQjMCExHzAdBgNVBAMTFlByaXZhdGVM"+
            "YWJlbDQtMjA0OC0xMTgwHQYDVR0OBBYEFHlHYQhB/TgEokvntcz1Q/ZJKxH4MIHx"+
            "BgNVHSMEgekwgeahgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5WZXJp"+
            "U2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazE6MDgG"+
            "A1UECxMxKGMpIDE5OTkgVmVyaVNpZ24sIEluYy4gLSBGb3IgYXV0aG9yaXplZCB1"+
            "c2Ugb25seTFFMEMGA1UEAxM8VmVyaVNpZ24gQ2xhc3MgMSBQdWJsaWMgUHJpbWFy"+
            "eSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEczghEAi1t1VoRUhQsAz684SM6x"+
            "pDANBgkqhkiG9w0BAQUFAAOCAQEAOU3PQZmBtakFtVI46TmEiWzkNKha59hsCUwk"+
            "GrpZpIc7cyHxk4HPv2hjWmf+NYUrocNdo0rCOhndMNbMTe/x0oGXylRaQ783i3qO"+
            "GY0PQ6iM8q9gsxWKs5WcPOCesyeYpDVyF+X8Kl2H04oNwtFFKvjA9KwqkzrVrhJw"+
            "COv7O+J37OgrZDV2zbra4NHLFNZxWJu+1T59ttnoJMUkZkxdkR92sxc+fw3GIYkv"+
            "sze4of9csm1J3mVSQvsOiNLtSh2/S+P4zHL6SA5ljknI1viZmDu3lD4xcQaH+mxZ"+
            "Uy7X3yvtX2MArBXtA7hVFozGaAPnIqhzC7G8oNpSWN0KDn/BgjGCAfgwggH0AgEB"+
            "MIHyMIHdMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAd"+
            "BgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOzA5BgNVBAsTMlRlcm1zIG9m"+
            "IHVzZSBhdCBodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhIChjKTA5MR4wHAYD"+
            "VQQLExVQZXJzb25hIE5vdCBWYWxpZGF0ZWQxNzA1BgNVBAMTLlZlcmlTaWduIENs"+
            "YXNzIDEgSW5kaXZpZHVhbCBTdWJzY3JpYmVyIENBIC0gRzMCEBWtc/sw71Uv3fNT"+
            "07fYCZ0wCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ"+
            "KoZIhvcNAQkFMQ8XDTEyMTAxODA5NDEwNVowIwYJKoZIhvcNAQkEMRYEFIb35Df6"+
            "paf84V0d3Lnq6uo3dme4MA0GCSqGSIb3DQEBAQUABIGAeuVTUPQJERvoxiebyykU"+
            "0loyLQyC0tikkpzDVAHPKkt6B3cV4X3D1arnypF2o0mDvWLEX0PguFEniS+YgM/y"+
            "ldjDVL4nR8ueFP5yA0G6G5SmnT999DQYGLw0tAaedNQUDL6ockSal5UgJU8sTLls"+
            "5cAYmQk3LgOGpAHWS99dOWA=";
}
