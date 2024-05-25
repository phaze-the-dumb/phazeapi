import { FastifyInstance } from "fastify";
import { findUserFromToken } from "../sessionUtils";

const PHAZE_TEIRS: string[] = [ '23051636' ];

export let main = async ( fastify: FastifyInstance ) => {
  fastify.get<{ Querystring: { token: string } }>('/id/v1/patreon', { schema: { tags: [ 'Internal' ] } }, async ( req, reply ) => {
    let { user } = await findUserFromToken(req, reply);
    if(!user)return;

    reply.redirect(`https://www.patreon.com/oauth2/authorize?response_type=code&client_id=${process.env.PATREON_CLIENT_ID}&scope=identity&redirect_uri=https://api.phazed.xyz/id/v1/patreon/callback&state=${req.query.token}`);
  })

  fastify.get<{ Querystring: { code: string, state: string } }>('/id/v1/patreon/callback', { schema: { tags: [ 'Internal' ] } }, async ( req, reply ) => {
    let { user } = await findUserFromToken(req, reply);
    if(!user)return;

    if(user.patreon){
      if(user.patreon.lastUpdate + 3.6e+6 > Date.now())return reply.send({ ok: false, error: 'You can only refresh once an hour.' });
    }

    let dataReq = await fetch('https://www.patreon.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `code=${req.query.code}&grant_type=authorization_code&client_id=${process.env.PATREON_CLIENT_ID}&client_secret=${process.env.PATREON_CLIENT_SECRET}&redirect_uri=https://api.phazed.xyz/id/v1/patreon/callback`
    })

    let data = await dataReq.json();

    let userReq = await fetch('https://www.patreon.com/api/oauth2/v2/identity?fields%5Btier%5D=title,amount_cents&fields%5Bmember%5D=patron_status,is_follower,full_name&include=memberships.currently_entitled_tiers', {
      headers: {
        'Authorization': 'Bearer ' + data.access_token
      }
    })

    let puser = await userReq.json();

    user.patreon = {
      id: puser.data.id,
      currentTiers: [],
      lastUpdate: 0,
      refreshToken: data.refresh_token
    }

    user.patreon.lastUpdate = Date.now();
    user.patreon.currentTiers = puser.included[0].relationships.currently_entitled_tiers.data.filter(( x: any ) => PHAZE_TEIRS.indexOf(x.id) !== -1);

    await user.save();
    reply.redirect('https://id.phazed.xyz');
  })

  fastify.get<{ Querystring: { token: string } }>('/id/v1/patreon/refresh', { schema: { tags: [ 'Internal' ] } }, async ( req, reply ) => {
    let { user } = await findUserFromToken(req, reply);
    if(!user)return;

    console.log(user.patreon);
    if(!user.patreon)return reply.send({ ok: false, error: 'You need to login first.' });
    if(user.patreon.lastUpdate + 3.6e+6 > Date.now())return reply.send({ ok: false, error: 'You can only refresh once an hour.' });

    let dataReq = await fetch('https://www.patreon.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `refresh_token=${user.patreon.refreshToken}&grant_type=refresh_token&client_id=${process.env.PATREON_CLIENT_ID}&client_secret=${process.env.PATREON_CLIENT_SECRET}&redirect_uri=https://api.phazed.xyz/id/v1/patreon/callback`
    })

    let data = await dataReq.json();

    let userReq = await fetch('https://www.patreon.com/api/oauth2/v2/identity?fields%5Btier%5D=title,amount_cents&fields%5Bmember%5D=patron_status,is_follower,full_name&include=memberships.currently_entitled_tiers', {
      headers: {
        'Authorization': 'Bearer ' + data.access_token
      }
    })

    let puser = await userReq.json();

    user.patreon.lastUpdate = Date.now();
    user.patreon.currentTiers = puser.included[0].relationships.currently_entitled_tiers.data.filter(( x: any ) => PHAZE_TEIRS.indexOf(x.id) !== -1);
    user.patreon.refreshToken = data.refresh_token;

    await user.save();
    reply.send({ ok: true });
  })

  fastify.get<{ Querystring: { token: string } }>('/id/v1/patreon/tiers', { schema: { tags: [ 'Internal' ] } }, async ( req, reply ) => {
    let { user } = await findUserFromToken(req, reply);
    if(!user)return;

    if(!user.patreon){
      return reply.send({ ok: false });
    }

    if(user.patreon.lastUpdate + 8.64e+7 < Date.now()){
      let dataReq = await fetch('https://www.patreon.com/api/oauth2/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `refresh_token=${user.patreon.refreshToken}&grant_type=refresh_token&client_id=${process.env.PATREON_CLIENT_ID}&client_secret=${process.env.PATREON_CLIENT_SECRET}&redirect_uri=https://api.phazed.xyz/id/v1/patreon/callback`
      })

      let data = await dataReq.json();

      let userReq = await fetch('https://www.patreon.com/api/oauth2/v2/identity?fields%5Btier%5D=title,amount_cents&fields%5Bmember%5D=patron_status,is_follower,full_name&include=memberships.currently_entitled_tiers', {
        headers: {
          'Authorization': 'Bearer ' + data.access_token
        }
      })
  
      let puser = await userReq.json();

      user.patreon.lastUpdate = Date.now();
      user.patreon.currentTiers = puser.included[0].relationships.currently_entitled_tiers.data.filter(( x: any ) => PHAZE_TEIRS.indexOf(x.id) !== -1);
      user.patreon.refreshToken = data.refresh_token;
  
      await user.save();
    }

    reply.send({ ok: true, tiers: user.patreon.currentTiers });
  })
}