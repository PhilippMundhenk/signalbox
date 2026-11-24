// Texts that come from the server with a stable id (#204): rule titles and explanations (by rule
// id) and findings, read errors and setup steps (by message id and parameters). A catalogue entry
// translates them; without one the English text the server sent is shown.
import { tServer } from './i18n.js';

export const ruleTitle = (rule) => tServer(`rule.${rule.id}.title`, null, rule.title);
export const ruleExplanation = (rule) => tServer(`rule.${rule.id}.explanation`, null, rule.explanation);

// Finding (or anything with title/message/fix and optional message_id/params/fix_id/fix_params).
export const findingTitle = (f) => tServer(`rule.${f.rule_id}.title`, null, f.title);
export const findingMessage = (f) => tServer(f.message_id ? `msg.${f.message_id}` : '', f.params, f.message);
export const findingFix = (f) => (f.fix ? tServer(f.fix_id ? `msg.${f.fix_id}` : '', f.fix_params || f.params, f.fix) : null);

// Read errors and gaps share the shape {message, message_id, params, fix, fix_id, fix_params}.
export const stepTitle = (s) => tServer(s.title_id ? `msg.${s.title_id}` : '', s.params, s.title);

export const errorMessage = findingMessage;
export const errorFix = findingFix;

// An ApiError of a setup or Fix it request: body {message, message_id, params, fix, fix_id}.
export const apiMessage = (err) => findingMessage({ message: err.message, message_id: err.body && err.body.message_id, params: err.body && err.body.params });
export const apiFix = (err) => (err.body && err.body.fix ? findingFix({ fix: err.body.fix, fix_id: err.body.fix_id, params: err.body.params }) : null);
