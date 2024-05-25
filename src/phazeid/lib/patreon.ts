import { FastifyInstance } from "fastify";
import { findUserFromToken } from "../sessionUtils";

export let main = async ( fastify: FastifyInstance ) => {
  fastify.get<{ Querystring: { token: string } }>('/id/v1/patreon', async ( req, reply ) => {
    let { user } = await findUserFromToken(req, reply);
    if(!user)return;

    reply.redirect(`https://www.patreon.com/oauth2/authorize?response_type=code&client_id=${process.env.PATREON_CLIENT_ID}&scope=identity&redirect_uri=https://api.phazed.xyz/id/v1/patreon/callback&state=${req.query.token}`);
  })

  fastify.get<{ Querystring: { code: string, state: string } }>('/id/v1/patreon/callback', async ( req, reply ) => {
    let dataReq = await fetch('https://www.patreon.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `code=${req.query.code}&grant_type=authorization_code&client_id=${process.env.PATREON_CLIENT_ID}&client_secret=${process.env.PATREON_CLIENT_SECRET}&redirect_uri=https://api.phazed.xyz/id/v1/patreon/callback`
    })

    let data = await dataReq.json();

    let userReq = await fetch('https://www.patreon.com/api/oauth2/v2/identity?fields%5Bmember%5D=patron_status,is_follower,full_name&include=memberships.currently_entitled_tiers', {
      headers: {
        'Authorization': 'Bearer ' + data.access_token
      }
    })

    let user = await userReq.json();
    reply.send(user);
  })
}