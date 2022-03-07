#!/bin/bash
cd "$(dirname "$0")"

truncate -s 0 ../data/variables.yaml
truncate -s 0 ../.authorizer_env

tenant_id="CONFIGURATION_TENANT_ID\="
workspace="ACP_WORKSPACE\="
tenant_url="CONFIGURATION_TENANT_URL\="
tid=$(sed -n "s/$tenant_id//p" ../.env)
ws=$(sed -n "s/$workspace//p" ../.env)
tu=$(sed -n "s/$tenant_url//p" ../.env)
echo tenant_id: $tid >> ../data/variables.yaml
echo workspace: $ws >> ../data/variables.yaml

echo ACP_ISSUER_URL\=$tu/system >> ../.authorizer_env
echo "TOKEN_EXCHANGE_ENABLED=true" >> ../.authorizer_env
echo "ACP_CLIENT_ID=c85cgj5t9c9vscu6k9tg" >> ../.authorizer_env
echo "ACP_CLIENT_SECRET=ytFAm6jjtNx88JRN8l4ayrzcXh7ouuu0av_MBC5iCk4" >> ../.authorizer_env
echo "ACP_SERVER_ID=system" >> ../.authorizer_env
echo "ACP_TENANT_ID=$tid" >> ../.authorizer_env