import chalk from 'chalk';
import * as debugLib from 'debug';
import { v4 as uuidv4 } from 'uuid';
import { getCodeAnalysisAndParseResults } from './analysis';
import { getSastSettings } from './settings';
import {
  getCodeDisplayedOutput,
  getPrefix,
  getMeta,
} from './format/output-format';
import { EcosystemPlugin } from '../../ecosystems/types';
import { FailedToRunTestError, NoSupportedSastFiles } from '../../errors';
import { jsonStringifyLargeObject } from '../../json';
import * as analytics from '../../analytics';
import { uploadCodeReport } from './report';

const debug = debugLib('snyk-code');

export const codePlugin: EcosystemPlugin = {
  // We currently don't use scan/display. we will need to consolidate ecosystem plugins
  // to accept flows that act differently in the `testDependencies` step, as we have here
  async scan() {
    return null as any;
  },
  async display() {
    return '';
  },
  async test(paths, options) {
    const requestId = uuidv4();
    debug(`Request ID: ${requestId}`);
    try {
      analytics.add('sast-scan', true);
      const sastSettings = await getSastSettings(options);
      // Currently code supports only one path
      const path = paths[0];

      const sarifTypedResult = await getCodeAnalysisAndParseResults(
        path,
        options,
        sastSettings,
        requestId,
      );

      if (!sarifTypedResult) {
        throw new NoSupportedSastFiles();
      }
      const numOfIssues = sarifTypedResult!.runs?.[0].results?.length || 0;
      analytics.add('sast-issues-found', numOfIssues);
      let newOrg = options.org;
      if (!newOrg && sastSettings.org) {
        newOrg = sastSettings.org;
      }

      let readableResult: string;

      // Share results (CLI upload)
      // WIP prototype implementation
      // TODO: separate flows in order to do analysis orchestration in API and not send issue data from client.
      // TODO: Better define what happens to other options like JSON/Sarif output when this is set.
      if (options.report) {
        const projectId = options['project-id'];
        // TODO: what kind of sanitisation does this need? What characters are supported? Should it be slug-ified?
        const projectName = options['project-name'];

        if (!projectId && (!projectName || projectName?.trim().length === 0)) {
          throw new FailedToRunTestError('No project ID or name specified');
        }

        // TODO: sanitisation/slugify
        const targetRef = options['target-reference'];

        readableResult = await uploadCodeReport({
          org: newOrg ?? null,
          projectId,
          projectName,
          targetRef,
          results: sarifTypedResult,
        });
      } else {
        const meta = getMeta({ ...options, org: newOrg }, path);
        const prefix = getPrefix(path);
        readableResult = getCodeDisplayedOutput(
          sarifTypedResult!,
          meta,
          prefix,
        );

        if (numOfIssues > 0 && options['no-markdown']) {
          sarifTypedResult.runs?.[0].results?.forEach(({ message }) => {
            delete message.markdown;
          });
        }

        if (options.sarif || options.json) {
          readableResult = jsonStringifyLargeObject(sarifTypedResult);
        }
      }

      let sarifResult: string | undefined;
      if (options['sarif-file-output']) {
        sarifResult = jsonStringifyLargeObject(sarifTypedResult);
      }
      let jsonResult: string | undefined;
      if (options['json-file-output']) {
        jsonResult = jsonStringifyLargeObject(sarifTypedResult);
      }

      if (numOfIssues > 0) {
        throwIssuesError({ readableResult, sarifResult, jsonResult });
      }
      return sarifResult ? { readableResult, sarifResult } : { readableResult };
    } catch (error) {
      let err: Error;
      if (isCodeClientError(error)) {
        const isUnauthorized = isUnauthorizedError(error)
          ? 'Unauthorized: '
          : '';
        err = new FailedToRunTestError(
          `${isUnauthorized}Failed to run 'code test'`,
          error.statusCode,
        );
      } else if (error instanceof Error) {
        err = error;
      } else if (isUnauthorizedError(error)) {
        err = new FailedToRunTestError(error.message, error.code);
      } else {
        err = new Error(error);
      }
      debug(
        chalk.bold.red(
          `requestId: ${requestId} statusCode:${error.code ||
            error.statusCode}, message: ${error.statusText || error.message}`,
        ),
      );
      throw err;
    }
  },
};

function isCodeClientError(error: object): boolean {
  return (
    error.hasOwnProperty('statusCode') &&
    error.hasOwnProperty('statusText') &&
    error.hasOwnProperty('apiName')
  );
}

function isUnauthorizedError(error: any): boolean {
  return (
    error.statusCode === 401 ||
    error.statusCode === 403 ||
    error.code === 403 ||
    error.code === 401
  );
}

function throwIssuesError(args: {
  readableResult: string;
  sarifResult: string | undefined;
  jsonResult: string | undefined;
}): Error {
  const err = new Error(args.readableResult) as any;
  err.code = 'VULNS';
  if (args.sarifResult !== undefined) {
    err.sarifStringifiedResults = args.sarifResult;
  }
  if (args.jsonResult !== undefined) {
    err.jsonStringifiedResults = args.jsonResult;
  }
  throw err;
}
