import { createCanvas, loadImage } from "canvas";
import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";

const S3 = new S3Client({
  region: 'auto',
  endpoint: 'https://'+process.env.ACCOUNT_ID+'.r2.cloudflarestorage.com',
  credentials: {
    accessKeyId: process.env.KEY_ID!,
    secretAccessKey: process.env.ACCESS_KEY!
  }
});

export let generateAvi = ( username: string, id: string ) => {
  let canvas = createCanvas(300, 300);
  let ctx = canvas.getContext("2d");

  ctx.fillStyle = `hsl(${Math.floor(Math.random() * 360)}, 100%, 50%)`;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.font = '100px Arial';
  ctx.fillStyle = '#fff';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';

  ctx.fillText(username[0], canvas.width / 2, canvas.height / 2);

  S3.send(new PutObjectCommand({
    Bucket: 'phazecdn',
    Body: canvas.toBuffer('image/png'),
    Key: 'id/avatars/' + id + '.png',
    ContentType: 'image/png'
  }))
    .then(() => console.log(`Uploaded avatar for ${username} (${id})`));

  console.log(`Uploading avatar for ${username} (${id})`);
}

export let upload = ( binaryData: Buffer, id: string ) => {
  return new Promise<void>(async ( res, rej ) => {
    console.log(`Uploading avatar for ${id}`);

    let canvas = createCanvas(300, 300);
    let ctx = canvas.getContext('2d');

    let img = await loadImage(binaryData);
    ctx.drawImage(img, 0, 0, 300, 300);

    await S3.send(new PutObjectCommand({
      Bucket: 'phazecdn',
      Body: canvas.toBuffer('image/png'),
      Key: 'id/avatars/' + id + '.png',
      ContentType: 'image/png'
    }))

    console.log(`Uploaded avatar for ${id}`)
    res();
  })
}

export let deleteAvi = async ( id: string ) => {
  await S3.send(new DeleteObjectCommand({
    Bucket: 'phazecdn',
    Key: 'id/avatars/' + id + '.png'
  }))
}