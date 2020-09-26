const { sprintf } = require('printj');
const fmt         = require('./fmt.js');

module.exports = {

  assumeRole: async (config, logger, STS, roleAttributeValue, SAMLAssertion) => {
    const rePrincipal      = /arn:aws:iam:[^:]*:[0-9]+:saml-provider\/[^,]+/i;
    const reRole           = /arn:aws:iam:[^:]*:([0-9]+):role\/([^,]+)/i;
    const principalMatches = roleAttributeValue.match(rePrincipal);
    const roleMatches      = roleAttributeValue.match(reRole);
    const accountNumber    = roleMatches[1];
    const roleName         = roleMatches[2];

    // Get the alias and duration of the account if it exists.
    // Otherwise, use the account number and 3600.
    // TODO: It may make sense to extract this into a function.

    const durationSeconds = (
                              config.AccountAliases
                              && config.AccountAliases
                                       .filter(
                                         x => x.AccountNumber
                                         === accountNumber,
                                       )
                                       .reduce((acc, duration) => duration.DurationSeconds, null)
                            )
                            || 3600;

    const roleAccount = (
                          config.AccountAliases
                          && config.AccountAliases
                                   .filter(
                                     x => x.AccountNumber
                                     === accountNumber,
                                   )
                                   .reduce((acc, alias) => alias.Alias, null)
                        )
                        || accountNumber;


    const params = {
                     PrincipalArn:    principalMatches[0],
                     RoleArn:         roleMatches[0],
                     DurationSeconds: durationSeconds,
                     SAMLAssertion,
                   };
    try
    {
      const response = await STS.assumeRoleWithSAML(params).promise();
      logger.info(sprintf(fmt.ASSUME_ROLE_SUCCESS, roleAccount, roleName));

      return {
               accountNumber,
               roleName,
               credentials: response.Credentials,
             };
    }
    catch (e)
    {
      logger.error(e.message);
      logger.debug(e.stack);
      return null;
    }
  },
};
