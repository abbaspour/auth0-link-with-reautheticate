async function reauthenticateAndLink(user, context, callback) {

    const primary_provider = 'auth0';
    const primary_connection = 'Username-Password-Authentication';

    const domain_name = context.request.hostname;
    const url = `https://${domain_name}`;
    const mgmt_api_domain = `https://${domain_name}`; // canonical domain name

    if (user.identities[0].provider === primary_provider) // primary is ok, nothing to do
        return callback(null, user, context);

    // todo: pkce flow, store nonce & code_verifier in user object

    if (context.protocol !== "redirect-callback") {
        context.redirect = {
            url: `${url}/authorize?client_id=${context.clientID}&nonce=mynonce&response_type=code&redirect_uri=https%3A%2F%2F${domain_name}%2Fcontinue&connection=${primary_connection}&prompt=login&scope=openid+profile+email`
        };
        return callback(null, user, context);
    } else {
        const axios = require("axios").default;

        /*
        const primary_user_id = user.user_id;
        const secondary_user_id = '63746980fe17f1fc46f56cf5';
        const secondary_user_provider = 'auth0';
        */

        console.log("code --> ", context.request.query.code);
        const exchangeTokenOptions = {
            method: 'POST',
            url: `${url}/oauth/token`,
            headers: {
                'content-type': 'application/json',
            },
            // todo: add code_verifier
            data: {
                grant_type: 'authorization_code',
                client_id: context.clientID,
                code: context.request.query.code,
                redirect_uri: `${url}/continue`,
                scope: 'openid profile email'
            }
        };
        const resTE = await axios.request(exchangeTokenOptions);

        console.log("data from internal exchange -->", resTE.data);

        if (!resTE.data.id_token)
            return callback('missing id_token');

        // todo: verify nonce
        const jsonwebtoken = require('jsonwebtoken@8.5.0');

        const id_token = jsonwebtoken.decode(resTE.data.id_token);

        console.log('id_token', id_token);


        const primary_user_id = id_token.sub;
        const [secondary_user_provider, secondary_user_id] = user.user_id.split('|');

        const options = {
            "content-type": "application/json",
            Authorization: `Bearer ${auth0.accessToken}`,
        };

        const jsonBody = {
            provider: secondary_user_provider,
            user_id: secondary_user_id,
        };

        context.primaryUser = primary_user_id;

        console.log(`linking with: `, jsonBody);

        try {
            const resp = await axios.post(
                `${mgmt_api_domain}/api/v2/users/${primary_user_id}/identities`,
                jsonBody,
                {
                    headers: options,
                }
            );
        } catch (error) {
            return callback(error);
        }

        return callback(null, user, context);
    }
}
