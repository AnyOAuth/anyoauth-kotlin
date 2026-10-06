// Generated standalone SDK checks. Canonical source: AnyOAuth/anyoauth.
import {spawn} from 'node:child_process';
for(const command of [["node","build.mjs"],["node","conformance.test.mjs","java","-cp","build/conformance.jar:build/anyoauth-client.jar:build/gson-2.13.2.jar","com.anyoauth.conformance.MainKt"]]){
  console.log('> '+command.join(' '));
  await new Promise((resolve,reject)=>{const child=spawn(command[0],command.slice(1),{stdio:'inherit'});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(new Error(command[0]+' failed: '+code)));});
}
