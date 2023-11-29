import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'
// import { certificate } from '../../lambda/auth'

const logger = createLogger('auth')

const jwksUrl = 'https://test-endpoint.auth0.com/.well-known/jwks.json'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJQOTgjR/zn1AtMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi14NmI3anQyM3kweHRjYTB6LnVzLmF1dGgwLmNvbTAeFw0yMzExMjkw
MzA3NTNaFw0zNzA4MDcwMzA3NTNaMCwxKjAoBgNVBAMTIWRldi14NmI3anQyM3kw
eHRjYTB6LnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALI5uozA2a6FqsEal4gWQPxKWsTiL6xmXhciCMZaD928ui2EFHn41Uof22qE
CR1iTC36ppJ2KC015Dcnt0v+SS451CZdwsIBMOZZsUiHmMQZwR8k11QOaRIocdG6
SirifJ4wyo72JNsP6s5sDEVz8/LyBSzOt6xjCS9kOuxFcoScmDJ6ybh31bt5BzWm
s3PYmZkuryGuCtYTgbGoURy1m0iQcMTpxDVIpXUktl7SmeaRcx5PGRKCEIEPZKtG
iqruYnSgPYzmO+P2oNNP9Z7ED2lzEDp5ZyGSlU44V6B673jD1FCvwzBKRb7oWBc0
Hhs59qZXnkI52bTnw/7fjGEu8MECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUXxKCKQtxJBNkVo0UmLVXH16/7+cwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQCdNHAIucH6Cuk3DJuYxEEoBnX5JcaKjGLmRxl+1Kvp
/56m8ujWndn7w5pyF8pfilQxGi5/AWq4mwzG0NVTvJSLX/QOUaM4YB9dMVvfz0y4
fjjGr1kYZ/8bS/2pa9nD+Y/Vy4yC4+vUWDC8o2t62BNcql+pS3jZW53EH4CqRmd8
+J+3JAvuWWQqVSGxDtPa7YYQ3NNYw2UsYjom+qQeiMeMwuVbcdoA/P8IwMcwMOf3
8oUEj/EpwLFlgS6JrWCnQBgp2VHLd5Udau/WAIwyFKTolLKVJ333sMHe/SmMYLT9
7d8bW08PgYQAAAFLDfyQ8iXxbvxLLtoNfOEs8lT0j2qn
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  // TODO: Implement token verification
  jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
  return jwt;
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
