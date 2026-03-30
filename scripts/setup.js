/**
 * Génère le hash bcrypt du mot de passe admin initial.
 * Usage : node scripts/setup.js
 * Copiez la valeur ADMIN_PASSWORD_HASH dans Railway > Variables.
 */
'use strict';

const bcrypt   = require('bcryptjs');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

rl.question('Mot de passe admin (8 caractères min) : ', async (pwd) => {
  rl.close();

  if (!pwd || pwd.length < 8) {
    console.error('\n[ERREUR] Mot de passe trop court.');
    process.exit(1);
  }

  const hash = await bcrypt.hash(pwd, 12);

  console.log('\n✅ Hash généré. Ajoutez cette variable dans Railway > Variables :\n');
  console.log(`ADMIN_PASSWORD_HASH=${hash}`);
  console.log('\nNe partagez jamais cette valeur.');
});
