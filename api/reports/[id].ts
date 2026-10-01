import { handleReportRequest } from '../../src/report-request.ts';

export function GET(request: Request): Promise<Response> {
	return handleReportRequest(request);
}
