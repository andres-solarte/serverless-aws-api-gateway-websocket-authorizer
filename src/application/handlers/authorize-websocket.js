const jwtDecode = require('jwt-decode')
const fetch = require('node-fetch')


const UNAUTHORIZED = 'Unauthorized'
const AUTHORIZATION_TOKEN_NOT_PRESENT = `${UNAUTHORIZED}, token not present`
const PUBLIC_KEY_NOT_FOUND = `${UNAUTHORIZED}, public key not found in jwks.json`
const SIGNATURE_VERIFICATION_FAILED = `${UNAUTHORIZED}, signature verification failed`
const TOKEN_EXPIRED = `${UNAUTHORIZED}, token is expired`


const generatePolicy = (principalId, effect, resource) => {
    let authResponse = {
        principalId
    }

    if (effect && resource) {
        const statement = {
            Action: 'execute-api:Invoke',
            Effect: effect,
            Resource: resource
        }

        const policyDocument = {
            Version: '2012-10-17',
            Statement: [statement]
        }

        authResponse.policyDocument = policyDocument
    }

    return authResponse
}

const generateAllow = (principalId, resource) => {
    return generatePolicy(principalId, 'Allow', resource)
}

const decodeJwtHeader = (jwt) => {
    try {
        return jwtDecode(jwt, { header: true })
    } catch (error) {
        throw SIGNATURE_VERIFICATION_FAILED
    }
}

const decodeJwtPayload = (jwt) => {
    try {
        return jwtDecode(jwt)
    } catch (error) {
        throw SIGNATURE_VERIFICATION_FAILED
    }
}

const verifyPublicKey = async (issuer, kid) => {
    const cognitoIdentityPoolUrl = `${issuer}/.well-known/jwks.json`
    const rawResponse = await fetch(cognitoIdentityPoolUrl)
    const jsonResponse = await rawResponse.json()

    if (rawResponse.ok) {
        const { keys } = jsonResponse
        const foundKey = keys.find(key => kid === key.kid)

        if (!foundKey)
            throw PUBLIC_KEY_NOT_FOUND
    } else {
        throw PUBLIC_KEY_NOT_FOUND
    }
}

const verifyTokenExpiration = (tokenExpiration) => {
    const currentTimestamp = Math.floor(new Date() / 1000)

    if (currentTimestamp > tokenExpiration) {
        throw TOKEN_EXPIRED
    }
}

const handler = async (event, context) => {
    const {
        queryStringParameters: { Authorization },
        methodArn
    } = event

    try {
        if (!Authorization)
            throw AUTHORIZATION_TOKEN_NOT_PRESENT

        const decodedJwtHeader = decodeJwtHeader(Authorization, { header: true })
        const decodedJwtPayload = decodeJwtPayload(Authorization)

        const { kid } = decodedJwtHeader
        const { iss, exp } = decodedJwtPayload

        await verifyPublicKey(iss, kid)
        verifyTokenExpiration(exp)

        return context.succeed(generateAllow('me', methodArn))
    } catch (error) {
        return context.fail(error)
    }
}

module.exports = { handler }
