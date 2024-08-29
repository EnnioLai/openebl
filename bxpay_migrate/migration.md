# Migration BlueX Pay organizations to OpenEBL

## Configuration of the migration tool

1. Application Key
1. BU Server URL
1. Cert Authority URL
1. Certificate Authority Cert ID
1. Certificate Valid Duration

## Input/Output of the migration tool

The tool reads `migration.csv` and write back to the same file.

## Steps for each organization of BlueXPay

1. Create a new `Business Unit` under the `application` in `BU Server`. Write back the `Business Unit ID` back to the `CSV` file.
1. Create a `BusinessUnitAuthentication` for the `Business Unit` in `BU Server`. Write back the `Business Unit Authentication ID` back to the `CSV` file.
1. Deliver the `CSR` of `BusinessUnitAuthentication` to the cert authority via `POST /cert`. Write the `Cert ID` back to the `CSV` file.
1. Issue the `Cert` of `BusinessUnitAuthentication` via `POST /cert/{cert_id}`. Write the `Cert` back to the `CSV` file.
