const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const client = new SecretManagerServiceClient();

const PROJECT_ID = 'seasonstats';

const secrets = {};

async function loadSecret(secretName) {
  const [version] = await client.accessSecretVersion({
    name: `projects/${PROJECT_ID}/secrets/${secretName}/versions/latest`,
  });

  return version.payload.data.toString('utf8');
}

async function loadAllSecrets() {
  const secretNames = [
    'user-password',
    'admin-password',
    'openai-api-key',
    'jwt-secret',
    'mongodb-password',
    'mongodb-uri',
  ];

  for (const name of secretNames) {
    secrets[name] = await loadSecret(name);
  }
}

function getSecret(name) {
  if (!(name in secrets)) {
    throw new Error(`Secret "${name}" has not been loaded.`);
  }
  return secrets[name];
}

module.exports = {
  loadAllSecrets,
  getSecret,
};
