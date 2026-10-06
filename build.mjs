// Docs: docs/sdk/contract.md
// Direct compiler path, also used on CI without a Gradle distribution.
import { mkdir, access, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
await mkdir('build',{recursive:true});
const jar='build/gson-2.13.2.jar';
try { await access(jar); } catch {
  const response=await fetch('https://repo.maven.apache.org/maven2/com/google/code/gson/gson/2.13.2/gson-2.13.2.jar');
  if (!response.ok) throw new Error(`Gson download failed: ${response.status}`);
  await writeFile(jar,new Uint8Array(await response.arrayBuffer()));
}
execFileSync('kotlinc',['src/main/kotlin/com/anyoauth/AnyOAuth.kt','-jvm-target','1.8','-d','build/anyoauth-client.jar'],{stdio:'inherit'});
execFileSync('kotlinc',['src/test/kotlin/com/anyoauth/conformance/Main.kt','src/test/kotlin/com/anyoauth/modelchecks/Main.kt','-classpath','build/anyoauth-client.jar:'+jar,'-include-runtime','-d','build/conformance.jar'],{stdio:'inherit'});
execFileSync('java',['-cp','build/conformance.jar:build/anyoauth-client.jar:'+jar,'com.anyoauth.modelchecks.MainKt'],{stdio:'inherit'});
