import users from "./db/users"
import sessions from "./db/sessions";
import { FastifyReply, FastifyRequest } from "fastify";
import apps from "./db/app";

let ipLocCache: any = {};

let getIpInfo = async ( ip: string ) => {
  if(!ipLocCache[ip]){
    let ipReq = await fetch(`https://ipinfo.io/${ip}?token=${process.env.IPINFO_KEY}`);
    let ipInfo = await ipReq.json();

    ipLocCache[ip] = ipInfo.region + ' ' + ipInfo.city;
  }

  return ipLocCache[ip];
}

export let cleanSessionsForUser = async ( userID: string ): Promise<any[]> => {
  let user = await users.findById(userID);
  if(!user)return [];

  let sessionsList = await sessions.find({ userID });
  let newSessionList: Array<string> = [];

  for(let i = 0; i < sessionsList.length; i++){ 
    let session = sessionsList[i];
    if(!session.valid)continue;

    if(session.expiresOn && session.expiresOn.getTime() > Date.now()){
      newSessionList.push(session._id!);
      continue;
    }

    await sessions.deleteOne({ _id: session._id });
  }

  user.sessions = newSessionList;
  await user.save();

  return sessionsList.filter(x => newSessionList.indexOf(x._id!) !== -1);
}

export let findUserFromToken = async ( 
  req: FastifyRequest<{ Querystring: { token: string, apptoken?: string } }>,
  reply: FastifyReply, 
  opts?: { dontRequireMfa?: boolean, dontRequireEmail?: boolean, dontRequireEmailVerification?: boolean, allowOAuth?: boolean }
): Promise<{ session: any, user: any, oauth: boolean }> => {
  if(!req.headers['cf-connecting-ip'])return reply.code(400).send({ ok: false, error: 'Invalid Request' });

  if(!req.query.token){
    reply.code(400).send({ ok: false, error: 'Invalid Query String' });
    return { session: null, user: null, oauth: false };
  }

  let oauth = false;
  let session = await sessions.findOne({ token: req.query.token });
  if(!session){
    if(opts?.allowOAuth && req.query.apptoken){
      session = await sessions.findOne({ oauthSession: req.query.token });
      oauth = true;

      let app = await apps.findOne({ token: req.query.apptoken });
      if(!app){
        reply.code(401).send({ ok: false, error: 'Invalid App' });
        return { session: null, user: null, oauth };
      }

      if(session?.oauthApps.indexOf(app._id!) === -1){
        reply.code(401).send({ ok: false, error: 'Invalid Token' });
        return { session: null, user: null, oauth };
      }

      if(!session){
        reply.code(401).send({ ok: false, error: 'Invalid Token' });
        return { session: null, user: null, oauth };
      }
    } else{
      reply.code(401).send({ ok: false, error: 'Invalid Token' });
      return { session: null, user: null, oauth };
    }
  }

  if(await getIpInfo(req.headers['cf-connecting-ip'].toString()) !== session.loc!.region + ' ' + session.loc!.city){
    reply.code(401).send({ ok: false, error: 'Invalid Session' });
    return { session: null, user: null, oauth };
  }
  
  let user = await users.findById(session.userID);
  if(!user){
    await sessions.deleteOne({ _id: session._id });
    reply.code(401).send({ ok: false, error: 'Invalid Session' });
    return { session: null, user: null, oauth };
  }

  if(!user.emailVerified && !opts?.dontRequireEmailVerification){
    reply.code(403).send({ ok: false, error: 'Verify Email' });
    return { session: null, user: null, oauth };
  }

  if(user.hasMfa && !session.hasMfa && !opts?.dontRequireMfa){
    reply.code(403).send({ ok: false, error: 'MFA Auth Needed' });
    return { session: null, user: null, oauth };
  }

  if(!session.expiresOn || session.expiresOn.getTime() < Date.now()){
    user.sessions = user.sessions.filter(x => x !== session!._id);
    await user.save();

    await sessions.deleteOne({ _id: session._id });
    reply.code(401).send({ ok: false, error: 'Invalid Session' });
    return { session: null, user: null, oauth };
  }

  if(!session.valid && !opts?.dontRequireEmail){
    reply.code(403).send({ ok: false, error: 'Session requires verification' });
    return { session: null, user: null, oauth };
  }

  return { session, user, oauth }
}