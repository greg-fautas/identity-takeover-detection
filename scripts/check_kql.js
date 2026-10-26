// Parse and type-check KQL with Microsoft's Kusto.Language (Bridge.NET build from @kusto/language-service-next).
// Usage: python scripts/extract_kql.py . | node scripts/check_kql.js <dir of @kusto/language-service-next>
// Exits 1 if any query has an Error-severity diagnostic or a rule maps a column the query does not return.
const fs = require('fs');
const path = require('path');

const [pkgDir, queriesFile] = process.argv.slice(2);
require(path.join(pkgDir, 'bridge.js'));
require(path.join(pkgDir, 'Kusto.Language.Bridge.js'));
const K = global.Kusto.Language;
const S = K.Symbols;

// The Sentinel columns these queries use. A rule that needs a new table or column fails until it is declared here.
const table = (name, schema) => new S.TableSymbol.$ctor7(name, schema, null);
const database = new S.DatabaseSymbol.ctor('SentinelWorkspace', [
  table('AuditLogs', '(TimeGenerated:datetime, OperationName:string, Result:string, InitiatedBy:dynamic, TargetResources:dynamic, LoggedByService:string, Category:string, AdditionalDetails:dynamic, ResultReason:string)'),
  table('SigninLogs', '(TimeGenerated:datetime, UserPrincipalName:string, IPAddress:string, ResultType:string, AppDisplayName:string, LocationDetails:dynamic, DeviceDetail:dynamic, UserAgent:string)'),
  table('AADNonInteractiveUserSignInLogs', '(TimeGenerated:datetime, UserPrincipalName:string, IPAddress:string, ResultType:string, AppDisplayName:string, LocationDetails:string, DeviceDetail:string, UserAgent:string)'),
  table('OfficeActivity', '(TimeGenerated:datetime, Operation:string, UserId:string, ClientIP:string, Parameters:string)'),
  table('ServiceNowTickets_CL', '(TimeGenerated:datetime, TicketNumber:string, CreatedAt:datetime, UpdatedAt:datetime, CallerUpn:string, OpenedByUpn:string, AssignedToUpn:string, ContactType:string, ShortDescription:string)'),
  // Sentinel's built-in watchlist function, typed per the PrivilegedAccounts watchlist
  new S.FunctionSymbol.$ctor5('_GetWatchlist', S.TableSymbol.From('(SearchKey:string, UserPrincipalName:string)'),
    [new S.Parameter.$ctor2('watchlistAlias', S.ScalarTypes.String)]),
]);
const globals = K.GlobalState.Default.WithDatabase(database);

// Columns a Sentinel rule reads from the query result: entity mappings, custom details, {{Column}} in alert overrides.
function mappedColumns(rule) {
  const cols = [];
  for (const em of rule.entityMappings || [])
    for (const fm of em.fieldMappings || []) cols.push([`entityMappings ${em.entityType}.${fm.identifier}`, fm.columnName]);
  for (const [key, col] of Object.entries(rule.customDetails || {})) cols.push([`customDetails.${key}`, col]);
  for (const [key, fmt] of Object.entries(rule.alertDetailsOverride || {}))
    for (const m of String(fmt).matchAll(/\{\{(\w+)\}\}/g)) cols.push([`alertDetailsOverride.${key}`, m[1]]);
  return cols;
}

const queries = JSON.parse(fs.readFileSync(queriesFile || 0, 'utf8'));  // no file arg: read stdin
if (!queries.length) { console.error('no queries found'); process.exit(1); }
let failed = false;
for (const q of queries) {
  const code = K.KustoCode.ParseAndAnalyze(q.text, globals);
  const analyzer = new K.Editor.KustoCodeService.ctor(code).GetAnalyzerDiagnostics(true);
  const diags = [...Bridge.toArray(code.GetDiagnostics()), ...Bridge.toArray(analyzer)];
  const columns = code.ResultType && code.ResultType.Columns
    ? new Set(Bridge.toArray(code.ResultType.Columns).map(c => c.Name)) : new Set();
  const missing = q.rule ? mappedColumns(q.rule).filter(([, col]) => !columns.has(col)) : [];

  const broken = missing.length > 0 || diags.some(d => d.Severity === 'Error');
  failed = failed || broken;
  console.log(`${broken ? 'FAIL' : 'ok  '} ${q.source}:${q.firstLine}`);
  for (const d of diags) {  // warnings and suggestions are printed but don't fail the build
    const line = q.text.slice(0, d.Start).split('\n').length - 1;
    console.log(`     [${d.Severity}] ${d.Code} line ${q.firstLine + line}: ${d.Message}`);
  }
  for (const [field, col] of missing) console.log(`     [Error] ${field} -> column "${col}" is not in the query result`);
}
process.exit(failed ? 1 : 0);
