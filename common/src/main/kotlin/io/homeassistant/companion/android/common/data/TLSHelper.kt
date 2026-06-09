package io.homeassistant.companion.android.common.data

import io.homeassistant.companion.android.common.data.keychain.KeyChainRepository
import io.homeassistant.companion.android.common.data.keychain.NamedKeyChain
import io.homeassistant.companion.android.common.data.keychain.NamedKeyStore
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.inject.Inject
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager
import okhttp3.OkHttpClient

class TLSHelper @Inject constructor(
    @NamedKeyChain private val keyChainRepository: KeyChainRepository,
    @NamedKeyStore private val keyStore: KeyChainRepository,
) {

    fun setupOkHttpClientSSLSocketFactory(builder: OkHttpClient.Builder) {
        val allTrustingTrustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                // No-op
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                // No-op
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(
            arrayOf(getMTLSKeyManagerForOKHTTP()),
            arrayOf<TrustManager>(allTrustingTrustManager),
            SecureRandom(),
        )

        builder.sslSocketFactory(sslContext.socketFactory, allTrustingTrustManager)
        builder.hostnameVerifier(HostnameVerifier { _, _ -> true })
    }

    private fun getMTLSKeyManagerForOKHTTP(): X509ExtendedKeyManager {
        return object : X509ExtendedKeyManager() {
            override fun getClientAliases(p0: String?, p1: Array<out Principal>?): Array<String> {
                return emptyArray()
            }

            override fun chooseClientAlias(p0: Array<out String>?, p1: Array<out Principal>?, p2: Socket?): String {
                return ""
            }

            override fun getServerAliases(p0: String?, p1: Array<out Principal>?): Array<String> {
                return arrayOf()
            }

            override fun chooseServerAlias(p0: String?, p1: Array<out Principal>?, p2: Socket?): String {
                return ""
            }

            override fun getCertificateChain(p0: String?): Array<X509Certificate>? {
                return keyChainRepository.getCertificateChain() ?: keyStore.getCertificateChain()
            }

            override fun getPrivateKey(p0: String?): PrivateKey? {
                return keyChainRepository.getPrivateKey() ?: keyStore.getPrivateKey()
            }
        }
    }
}
