import users from "./db/users"
import sessions from "./db/sessions";

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