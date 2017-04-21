import * as msRest from 'ms-rest';
import * as msRestAzure from 'ms-rest-azure';

import { ResourceManagementClient, ResourceModels } from 'azure-arm-resource';
import KeyVaultManagementClient = require('azure-arm-keyvault');
import * as KeyVaultManagementModels from '../node_modules/azure-arm-keyvault/lib/models';
import KeyVaultDataPlane = require('azure-keyvault');

// adal-node does not have types.
let AuthenticationContext = require('adal-node').AuthenticationContext;

class State {
    // service principal details for running the sample
    public clientId: string = process.env['CLIENT_ID'];
    public domain: string = process.env['DOMAIN'];
    public secret: string = process.env['APPLICATION_SECRET'];
    public subscriptionId: string = process.env['AZURE_SUBSCRIPTION_ID'];
    public objectId: string = process.env['OBJECT_ID'];

    // service principal details that we want give access to the key vault.
    public objectIdForKeyVault: string = process.env['OBJECT_ID_KEYVAULT_OPERATIONS'];
    public keyVaultSp: string = process.env['SP_KEYVAULT_OPERATIONS'];

    public options: string;
}

class KeyVaultSample {
    private resourceGroupName = Helpers.generateRandomId('testrg');
    private storageAccountName = Helpers.generateRandomId('testacc');
    private vaultName = Helpers.generateRandomId('testkv');

    private location = 'westus';
    private accType = 'Standard_LRS';
    private keyName = 'testkeyrandom99';

    private resourceClient: ResourceManagementClient;
    private kvManagementClient: KeyVaultManagementClient;
    private kvClient: KeyVaultDataPlane.KeyVaultClient;

    public static state = new State();

    constructor() { }

    public async execute(): Promise<boolean> {

        try {
            var credentials = await this.login();
            this.resourceClient = new ResourceManagementClient(credentials, KeyVaultSample.state.subscriptionId);
            this.kvManagementClient = new KeyVaultManagementClient(credentials, KeyVaultSample.state.subscriptionId);

            let kvCreds = new KeyVaultDataPlane.KeyVaultCredentials(this.authenticator);
            this.kvClient = new KeyVaultDataPlane.KeyVaultClient(kvCreds);

            let rg = await this.createResourceGroup()
            let vault = await this.createKeyVault();
            let vaultUri = vault.properties.vaultUri;

            // Note: 
            // proceed after a timeout.The reason of this is, keyvault is a network resource
            // and DNS registration takes some time. After talking with the keyvault team,
            // a delay of 5 seconds seems to be sufficient.
            await this.delay(5000);

            let keyBundle = await this.createKey(vaultUri);
            let keys = await this.getKeys(vaultUri);

            let secretBundle = await this.setSecret(vaultUri);
            let secrets = await this.getSecrets(vaultUri);

            let updatedVault = await this.updateKeyVault();

            let status = await this.cleanup();
        } catch (error) {
            return Promise.reject(error);
        }

        return Promise.resolve(true);
    }

    private authenticator(challenge: any, callback: any) {
        let context = new AuthenticationContext(challenge.authorization);

        return context.acquireTokenWithClientCredentials(challenge.resource, KeyVaultSample.state.clientId, KeyVaultSample.state.secret,
            function (err: any, tokenResponse: any) {
                if (err) throw err;
                // Calculate the value to be set in the request's Authorization header and resume the call.
                var authorizationValue = tokenResponse.tokenType + ' ' + tokenResponse.accessToken;

                return callback(null, authorizationValue);
            });
    }

    private delay<T>(millis: number, value?: T): Promise<T> {
        return new Promise((resolve) => setTimeout(() => resolve(value), millis))
    }

    private login(): Promise<msRestAzure.ApplicationTokenCredentials> {
        return msRestAzure.loginWithServicePrincipalSecret(KeyVaultSample.state.clientId, KeyVaultSample.state.secret, KeyVaultSample.state.domain, KeyVaultSample.state.options);
    }

    private createResourceGroup(): Promise<ResourceModels.ResourceGroup> {
        let groupParameters: ResourceModels.ResourceGroup = {
            location: this.location
        };

        console.log(`\n1. Creating resource group: ${this.resourceGroupName}`);
        return this.resourceClient.resourceGroups.createOrUpdate(this.resourceGroupName, groupParameters);
    }

    private createKeyVault(): Promise<KeyVaultManagementModels.Vault> {
        let keyPermissions: string[] = ['get', 'create', 'delete', 'list', 'update', 'import', 'backup', 'restore'];

        let permissions: KeyVaultManagementModels.Permissions = {
            keys: keyPermissions,
            secrets: ['all']
        }

        let accessPolicy: KeyVaultManagementModels.AccessPolicyEntry = {
            tenantId: KeyVaultSample.state.domain,
            objectId: KeyVaultSample.state.objectId,
            permissions: permissions
        };

        let vaultProps: KeyVaultManagementModels.VaultProperties = {
            sku: { name: 'standard' },
            accessPolicies: [accessPolicy],
            tenantId: KeyVaultSample.state.domain,
            enabledForDeployment: false
        };

        let createParams: KeyVaultManagementModels.VaultCreateOrUpdateParameters = {
            location: this.location,
            properties: vaultProps,
            tags: {}
        };

        console.log(`\n2. Creating key vault ${this.vaultName} in resource group: ${this.resourceGroupName}`);
        return this.kvManagementClient.vaults.createOrUpdate(this.resourceGroupName, this.vaultName, createParams);
    }

    private createKey(vaultUri: string): Promise<KeyVaultDataPlane.Models.KeyBundle> {
        let keyOperations: string[] = ['encrypt', 'decrypt', 'sign', 'verify', 'wrapKey', 'unwrapKey'];

        let attributes: KeyVaultDataPlane.KeyAttributes = {
            expires: new Date('2050-02-02T08:00:00.000Z'),
            notBefore: new Date('2016-01-01T08:00:00.000Z')
        };

        let keyOptions: KeyVaultDataPlane.CreateKeyOptions = {
            keyOps: keyOperations,
            keyAttributes: attributes
        };

        console.log(`\n3. Creating key ${this.keyName} in vault: ${this.vaultName}`);
        return this.kvClient.createKey(vaultUri, this.keyName, 'RSA', keyOptions);
    }

    private async updateKeyVault(): Promise<KeyVaultManagementModels.Vault> {
        let vault = await this.kvManagementClient.vaults.get(this.resourceGroupName, this.vaultName);

        let params: KeyVaultManagementModels.VaultCreateOrUpdateParameters = {
            location: vault.location,
            properties: vault.properties
        };

        let permissions: KeyVaultManagementModels.Permissions = {
            keys: ['get', 'list', 'import'],
            secrets: ['all']
        };

        let newAccessPolicyEntry: KeyVaultManagementModels.AccessPolicyEntry = {
            tenantId: KeyVaultSample.state.domain,
            objectId: KeyVaultSample.state.objectIdForKeyVault,
            applicationId: KeyVaultSample.state.keyVaultSp,
            permissions: permissions
        };

        params.properties.accessPolicies.push(newAccessPolicyEntry);

        console.log(`\n7. updating key vault: ${this.vaultName}`);
        return this.kvManagementClient.vaults.createOrUpdate(this.resourceGroupName, this.vaultName, params);
    }

    private getKeys(vaultUri: string): Promise<KeyVaultDataPlane.Models.KeyListResult> {
        console.log(`\n4. getting keys from vault: ${this.vaultName}`);
        return this.kvClient.getKeys(vaultUri);
    }

    private setSecret(vaultUri: string): Promise<KeyVaultDataPlane.Models.SecretBundle> {
        let attributes: KeyVaultDataPlane.Models.SecretAttributes = {
            expires: new Date('2050-02-02T08:00:00.000Z'),
            notBefore: new Date('2016-01-01T08:00:00.000Z')
        };

        let secretOptions = {
            contentType: 'test secret',
            secretAttributes: attributes
        };

        let secretName = 'mysecret';
        let secretValue = 'my shared secret';

        console.log(`\n5. setting secret ${secretName} in vault: ${this.vaultName}`);
        return this.kvClient.setSecret(vaultUri, secretName, secretValue, secretOptions);
    }

    private getSecrets(vaultUri: string): Promise<KeyVaultDataPlane.Models.SecretListResult> {
        console.log(`\n6. getting secrets from vault: ${this.vaultName}`);
        return this.kvClient.getSecrets(vaultUri);
    }

    private async cleanup(): Promise<boolean> {
        try {
            console.log(`\n8. deleting vault ${this.vaultName} and resource group ${this.resourceGroupName}`);
            await this.kvManagementClient.vaults.deleteMethod(this.resourceGroupName, this.vaultName);
            await this.resourceClient.resourceGroups.deleteMethod(this.resourceGroupName);
        } catch (error) {
            console.log(`Encountered error during resource cleanup: ${error}`);
            return false;
        }

        return true;
    }
}

class Helpers {
    static generateRandomId(prefix: string): string {
        return prefix + Math.floor(Math.random() * 10000);
    }

    static validateEnvironmentVariables(): void {
        let envs = [];
        if (!process.env['CLIENT_ID']) envs.push('CLIENT_ID');
        if (!process.env['DOMAIN']) envs.push('DOMAIN');
        if (!process.env['APPLICATION_SECRET']) envs.push('APPLICATION_SECRET');
        if (!process.env['AZURE_SUBSCRIPTION_ID']) envs.push('AZURE_SUBSCRIPTION_ID');
        if (envs.length > 0) {
            throw new Error(`please set/export the following environment variables: ${envs.toString()}`);
        }
    }
}

main();

async function main() {
    Helpers.validateEnvironmentVariables();
    let driver = new KeyVaultSample();
    await driver.execute();
}
