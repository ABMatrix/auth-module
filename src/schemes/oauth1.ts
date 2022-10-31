import requrl from 'requrl'
import type {
  RefreshableScheme,
  SchemePartialOptions,
  SchemeCheck,
  RefreshableSchemeOptions,
  UserOptions,
  SchemeOptions,
  HTTPResponse,
  EndpointsOption,
  TokenableSchemeOptions
} from '../types'
import type { Auth } from '../core'
import {
  encodeQuery,
  getProp,
  normalizePath,
  parseQuery,
  removeTokenPrefix,
  urlJoin,
  getDevice
} from '../utils'
import {
  RefreshController,
  RequestHandler,
  ExpiredAuthSessionError,
  Token,
  RefreshToken
} from '../inc'
import { BaseScheme } from './base'

export interface Oauth1SchemeEndpoints extends EndpointsOption {
  oauthToken: string
  authorization: string
  token: string
  userInfo: string
  logout: string | false
}

export interface Oauth1SchemeOptions
  extends SchemeOptions,
    TokenableSchemeOptions,
    RefreshableSchemeOptions {
  endpoints: Oauth1SchemeEndpoints
  user: UserOptions
  responseMode: 'query.jwt' | 'fragment.jwt' | 'form_post.jwt' | 'jwt'
  responseType: 'code' | 'token' | 'id_token' | 'none' | string
  grantType:
    | 'implicit'
    | 'authorization_code'
    | 'client_credentials'
    | 'password'
    | 'refresh_token'
    | 'urn:ietf:params:oauth:grant-type:device_code'
  accessType: 'online' | 'offline'
  redirectUri: string
  logoutRedirectUri: string
  clientId: string | number
  scope: string | string[]
  acrValues: string
  audience: string
  autoLogout: boolean
}

const DEFAULTS: SchemePartialOptions<Oauth1SchemeOptions> = {
  name: 'oauth1',
  accessType: null,
  redirectUri: null,
  logoutRedirectUri: null,
  clientId: null,
  audience: null,
  grantType: null,
  responseMode: null,
  acrValues: null,
  autoLogout: false,
  endpoints: {
    logout: null,
    authorization: null,
    token: null,
    userInfo: null
  },
  scope: [],
  token: {
    property: 'access_token',
    type: 'Bearer',
    name: 'Authorization',
    maxAge: 1800,
    global: true,
    prefix: '_token.',
    expirationPrefix: '_token_expiration.'
  },
  refreshToken: {
    property: 'refresh_token',
    maxAge: 60 * 60 * 24 * 30,
    prefix: '_refresh_token.',
    expirationPrefix: '_refresh_token_expiration.'
  },
  user: {
    property: false
  }
}

export class Oauth1Scheme<
    OptionsT extends Oauth1SchemeOptions = Oauth1SchemeOptions
  >
  extends BaseScheme<OptionsT>
  implements RefreshableScheme
{
  public req
  public token: Token
  public refreshToken: RefreshToken
  public refreshController: RefreshController
  public requestHandler: RequestHandler

  constructor(
    $auth: Auth,
    options: SchemePartialOptions<Oauth1SchemeOptions>,
    ...defaults: SchemePartialOptions<Oauth1SchemeOptions>[]
  ) {
    super(
      $auth,
      options as OptionsT,
      ...(defaults as OptionsT[]),
      DEFAULTS as OptionsT
    )

    this.req = $auth.ctx.req

    // Initialize Token instance
    this.token = new Token(this, this.$auth.$storage)

    // Initialize Refresh Token instance
    this.refreshToken = new RefreshToken(this, this.$auth.$storage)

    // Initialize Refresh Controller
    this.refreshController = new RefreshController(this)

    // Initialize Request Handler
    this.requestHandler = new RequestHandler(this, this.$auth.ctx.$axios)
  }

  protected get scope(): string {
    return Array.isArray(this.options.scope)
      ? this.options.scope.join(' ')
      : this.options.scope
  }

  protected get redirectURI(): string {
    const basePath = this.$auth.ctx.base || ''
    const path = normalizePath(
      basePath + '/' + this.$auth.options.redirect.callback
    ) // Don't pass in context since we want the base path
    return this.options.redirectUri || urlJoin(requrl(this.req), path)
  }

  protected get logoutRedirectURI(): string {
    return (
      this.options.logoutRedirectUri ||
      urlJoin(requrl(this.req), this.$auth.options.redirect.logout)
    )
  }

  check(checkStatus = false): SchemeCheck {
    const response = {
      valid: false,
      tokenExpired: false,
      refreshTokenExpired: false,
      isRefreshable: true
    }

    // Sync tokens
    const token = this.token.sync()
    this.refreshToken.sync()

    // Token is required but not available
    if (!token) {
      return response
    }

    // Check status wasn't enabled, let it pass
    if (!checkStatus) {
      response.valid = true
      return response
    }

    // Get status
    const tokenStatus = this.token.status()
    const refreshTokenStatus = this.refreshToken.status()

    // Refresh token has expired. There is no way to refresh. Force reset.
    if (refreshTokenStatus.expired()) {
      response.refreshTokenExpired = true
      return response
    }

    // Token has expired, Force reset.
    if (tokenStatus.expired()) {
      response.tokenExpired = true
      return response
    }

    response.valid = true
    return response
  }

  async mounted(): Promise<HTTPResponse | void> {
    const { tokenExpired, refreshTokenExpired } = this.check(true)

    // Force reset if refresh token has expired
    // Or if `autoLogout` is enabled and token has expired
    if (refreshTokenExpired || (tokenExpired && this.options.autoLogout)) {
      this.$auth.reset()
    }

    // Initialize request interceptor
    this.requestHandler.initializeRequestInterceptor(
      this.options.endpoints.token
    )

    // Handle callbacks on page load
    const redirected = await this._handleCallback()

    if (!redirected) {
      return this.$auth.fetchUserOnce()
    }
  }

  reset(): void {
    this.$auth.setUser(false)
    this.token.reset()
    this.refreshToken.reset()
    this.requestHandler.reset()
  }

  async login(
    _opts: { state?: string; params?; nonce?: string } = {}
  ): Promise<void> {
    const query = this.$auth.ctx.query
    if (!query.clientId) query.clientId = 'SBT'
    const response = await this.$auth.request({
      method: 'post',
      url: this.options.endpoints.oauthToken
    })
    const opts = {
      oauth_token: response.data
    }

    this.$auth.$storage.setUniversal(this.name + '.query', query)

    const url = this.options.endpoints.authorization + '?' + encodeQuery(opts)

    window.location.replace(url)
  }

  logout(): void {
    if (this.options.endpoints.logout) {
      const opts = {
        client_id: this.options.clientId + '',
        logout_uri: this.logoutRedirectURI
      }
      const url = this.options.endpoints.logout + '?' + encodeQuery(opts)
      window.location.replace(url)
    }
    return this.$auth.reset()
  }

  async fetchUser(): Promise<void> {
    if (!this.check().valid) {
      return
    }

    if (!this.options.endpoints.userInfo) {
      this.$auth.setUser({})
      return
    }

    const response = await this.$auth.requestWith(this.name, {
      url: this.options.endpoints.userInfo
    })

    this.$auth.setUser(response.data)
  }

  async _handleCallback(): Promise<boolean | void> {
    // Handle callback only for specified route
    if (
      this.$auth.options.redirect &&
      normalizePath(this.$auth.ctx.route.path, this.$auth.ctx) !==
        normalizePath(this.$auth.options.redirect.callback, this.$auth.ctx)
    ) {
      return
    }
    // Callback flow is not supported in server side
    if (process.server) {
      return
    }

    const hash = parseQuery(this.$auth.ctx.route.hash.substr(1))
    const parsedQuery = Object.assign({}, this.$auth.ctx.route.query, hash)
    // accessToken/idToken
    let token: string = parsedQuery[this.options.token.property] as string
    // refresh token
    let refreshToken: string

    if (this.options.refreshToken.property) {
      refreshToken = parsedQuery[this.options.refreshToken.property] as string
    }

    const query = this.$auth.$storage.getUniversal(this.name + '.query') as {
      [key: string]: string
    }

    // -- Authorization Code Grant --
    if (parsedQuery.oauth_verifier) {
      const response = await this.$auth.request({
        method: 'post',
        url: this.options.endpoints.token,
        baseURL: '',
        data: {
          code: parsedQuery.oauth_token,
          deviceName: query.deviceName ?? getDevice(),
          clientID: query.clientId,
          state: 'sbt',
          oauth2Type: this.name.toUpperCase(),
          oauthToken: parsedQuery.oauth_token,
          codeVerify: parsedQuery.oauth_verifier
        }
      })
      token = response.data
      refreshToken =
        (getProp(
          response.data,
          this.options.refreshToken.property
        ) as string) || refreshToken
    }

    if (!token || !token.length) {
      return
    }
    if (query.loginType) {
      if (query.origin) {
        const data = {
          result: 'agree',
          id: query.id,
          data: token
        }
        const targetOrigin = query.origin
        const iframe = query.iframe
        if (iframe === 'true') {
          window.parent?.postMessage(data, '*')
          return
        }
        window.opener?.postMessage(data, {
          targetOrigin
        })
        window.close()
        return
      }
      const link = document.createElement('a')
      link.setAttribute('href', `${query.scheme}:callback?token=${token}`)
      link.setAttribute('target', '_self')
      document.body.append(link)
      link.click()
      window.close()
      return true
    }

    // Set token
    this.token.set(token)

    // Store refresh token
    if (refreshToken && refreshToken.length) {
      this.refreshToken.set(refreshToken)
    }

    // Redirect to home
    if (this.$auth.options.watchLoggedIn) {
      this.$auth.redirect('home', true, query)
      return true // True means a redirect happened
    }
  }

  async refreshTokens(): Promise<HTTPResponse | void> {
    // Get refresh token
    const refreshToken = this.refreshToken.get()

    // Refresh token is required but not available
    if (!refreshToken) {
      return
    }

    // Get refresh token status
    const refreshTokenStatus = this.refreshToken.status()

    // Refresh token is expired. There is no way to refresh. Force reset.
    if (refreshTokenStatus.expired()) {
      this.$auth.reset()

      throw new ExpiredAuthSessionError()
    }

    // Delete current token from the request header before refreshing
    this.requestHandler.clearHeader()

    const response = await this.$auth
      .request({
        method: 'post',
        url: this.options.endpoints.token,
        baseURL: '',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        data: {
          refresh_token: removeTokenPrefix(
            refreshToken,
            this.options.token.type
          ),
          scopes: this.scope,
          client_id: this.options.clientId + '',
          grant_type: 'refresh_token'
        }
      })
      .catch((error) => {
        this.$auth.callOnError(error, { method: 'refreshToken' })
        return Promise.reject(error)
      })

    this.updateTokens(response)

    return response
  }

  protected updateTokens(response: HTTPResponse): void {
    const token = getProp(response.data, this.options.token.property) as string
    const refreshToken = getProp(
      response.data,
      this.options.refreshToken.property
    ) as string

    this.token.set(token)

    if (refreshToken) {
      this.refreshToken.set(refreshToken)
    }
  }
}
