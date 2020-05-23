/* global describe it */
/* eslint-env mocha */
const expect = require('unexpected');
const Sts    = require('../sts.js');
const mock   = require('./mock.js');

describe(
  '#assumeRole(config, logger, sts, roleAttributeValue, SAMLAssertion)',
  () => {
    describe('On failure of assumeRole...', () => {
      describe('When the log level is set to info...', () => {
        const mockConfig = {
                              AccountAliases: [
                                {
                                  AccountNumber: mock.accountNumber.lab,
                                  Alias:         'Lab',
                                },
                              ],
                            };

        const log = new mock.Log();

        it('Returns "null"', async () => {
          const actual = await Sts.assumeRole(
            mockConfig,
            new mock.Logger(log, 'info'),
            new mock.Sts(false),
            mock.roleAttributeValue.lab,
            mock.saml_assertion,
          );

          expect(actual, 'to be', null);
        });

        it('Logs the error', async () => {
          expect(log.entries('error'), 'to have length', 1);
          expect(log.entries('error')[0].message, 'to be', 'Fail!');
        });
      });


      describe('When the log level is set to debug...', () => {
        const mockConfig = {
                             AccountAliases: [
                               {
                                 AccountNumber: mock.accountNumber.lab,
                                 Alias:         'Lab',
                               },
                             ],
                           };

        const log = new mock.Log();

        it('Returns "null"', async () => {
          const actual = await Sts.assumeRole(
            mockConfig,
            new mock.Logger(log, 'debug'),
            new mock.Sts(false),
            mock.roleAttributeValue.lab,
            mock.saml_assertion,
          );

          expect(actual, 'to be', null);
        });

        it('Logs the error', async () => {
          expect(log.entries('error'), 'to have length', 1);
          expect(log.entries('error')[0].message, 'to be', 'Fail!');
        });

        it('Logs the full stack trace', async () => {
          expect(log.entries('debug'), 'to have length', 1);
          expect(log.entries('debug')[0].message, 'to contain', 'Fail!');
        });
      });
    });


    describe('With a Single Alias Configured...', () => {
      describe('When the role matches the alias...', () => {
        const mockConfig = {
                              AccountAliases: [
                                {
                                  AccountNumber: mock.accountNumber.lab,
                                  Alias:         'Lab',
                                },
                              ],
                            };

        const log = new mock.Log();

        it('Returns an Assumed Role Object', async () => {
          const actual = await Sts.assumeRole(
            mockConfig,
            new mock.Logger(log, 'info'),
            new mock.Sts(true),
            mock.roleAttributeValue.lab,
            mock.saml_assertion,
          );

          expect(actual, 'to equal', {
                                       accountNumber: mock.accountNumber.lab,
                                       roleName:      'MockRole',
                                       credentials:   mock.credentials,
                                     });
        });

        it('Logs the correct account name', async () => {
          expect(log.entries('info'), 'to have length', 1);
          expect(log.entries('info')[0].message, 'to contain', 'Lab');
        });
      });


      describe('When the role does not match the alias...', () => {
        const mockConfig = {
                              AccountAliases: [
                                {
                                  AccountNumber: mock.accountNumber.lab,
                                  Alias:         'Lab',
                                },
                              ],
                            };

        const log = new mock.Log();

        it('Returns an Assumed Role Object', async () => {
          const actual = await Sts.assumeRole(
            mockConfig,
            new mock.Logger(log, 'info'),
            new mock.Sts(true),
            mock.roleAttributeValue.sbx,
            mock.saml_assertion,
          );

          expect(actual, 'to equal', {
                                       accountNumber: mock.accountNumber.sbx,
                                       roleName:      'MockRole',
                                       credentials:   mock.credentials,
                                     });
        });

        it('Logs the correct account name', async () => {
          expect(log.entries('info'), 'to have length', 1);
          expect(log.entries('info')[0].message, 'to contain', mock.accountNumber.sbx);
        });
      });
    });


    describe('With Multiple Aliases Configured...', () => {
      describe('When the role matches an alias...', () => {
        const mockConfig = {
                              AccountAliases: [
                                {
                                  AccountNumber: mock.accountNumber.lab,
                                  Alias:         'Lab',
                                },
                                {
                                  AccountNumber: mock.accountNumber.sbx,
                                  Alias:         'Sandbox',
                                },
                                {
                                  AccountNumber: mock.accountNumber.dev,
                                  Alias:         'Dev',
                                },
                              ],
                            };

        const log = new mock.Log();

        it('Returns an Assumed Role Object', async () => {
          const actual = await Sts.assumeRole(
            mockConfig,
            new mock.Logger(log, 'info'),
            new mock.Sts(true),
            mock.roleAttributeValue.lab,
            mock.saml_assertion,
          );

          expect(actual, 'to equal', {
                                       accountNumber: mock.accountNumber.lab,
                                       roleName:      'MockRole',
                                       credentials:   mock.credentials,
                                     });
        });

        it('Logs the correct account name', async () => {
          expect(log.entries('info'), 'to have length', 1);
          expect(log.entries('info')[0].message, 'to contain', 'Lab');
        });
      });


      describe('When the role does not match any aliases...', () => {
        const mockConfig = {
                              AccountAliases: [
                                {
                                  AccountNumber: mock.accountNumber.lab,
                                  Alias:         'Lab',
                                },
                                {
                                  AccountNumber: mock.accountNumber.sbx,
                                  Alias:         'Sandbox',
                                },
                                {
                                  AccountNumber: mock.accountNumber.dev,
                                  Alias:         'Dev',
                                },
                              ],
                            };

        const log = new mock.Log();

        it('Returns an Assumed Role Object', async () => {
          const actual = await Sts.assumeRole(
            mockConfig,
            new mock.Logger(log, 'info'),
            new mock.Sts(true),
            mock.roleAttributeValue.prod,
            mock.saml_assertion,
          );

          expect(actual, 'to equal', {
                                       accountNumber: mock.accountNumber.prod,
                                       roleName:      'MockRole',
                                       credentials:   mock.credentials,
                                     });
        });

        it('Logs the correct account name', async () => {
          expect(log.entries('info'), 'to have length', 1);
          expect(log.entries('info')[0].message, 'to contain', mock.accountNumber.prod);
        });
      });
    });
  },
);
