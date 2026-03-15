import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';
import { execSync } from 'child_process';

export class PromptShield implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Prompt Shield',
		name: 'promptShield',
		icon: 'file:icon.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{ $parameter["operation"] }}',
		description: 'Scan text for prompt injection attacks and PII',
		defaults: {
			name: 'Prompt Shield',
		},
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		usableAsTool: true,
		credentials: [
			{
				name: 'promptShieldApi',
				required: false,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Scan',
						value: 'scan',
						description: 'Scan text for prompt injection attacks',
						action: 'Scan text for prompt injection attacks',
					},
					{
						name: 'PII Scan',
						value: 'piiScan',
						description: 'Scan text for personally identifiable information',
						action: 'Scan text for PII',
					},
					{
						name: 'PII Redact',
						value: 'piiRedact',
						description: 'Redact personally identifiable information from text',
						action: 'Redact PII from text',
					},
				],
				default: 'scan',
			},
			{
				displayName: 'Input Text',
				name: 'inputText',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'Enter text to scan...',
				description: 'The text to scan for prompt injection or PII',
				typeOptions: {
					rows: 4,
				},
			},
			{
				displayName: 'JSON Output',
				name: 'jsonOutput',
				type: 'boolean',
				default: true,
				description: 'Whether to return structured JSON output from the CLI',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		let cliPath = 'prompt-shield';
		try {
			const credentials = await this.getCredentials('promptShieldApi');
			if (credentials?.pythonPath) {
				cliPath = credentials.pythonPath as string;
			}
		} catch {
			// Credentials are optional; fall back to default CLI path
		}

		for (let i = 0; i < items.length; i++) {
			try {
				const operation = this.getNodeParameter('operation', i) as string;
				const inputText = this.getNodeParameter('inputText', i) as string;
				const jsonOutput = this.getNodeParameter('jsonOutput', i) as boolean;

				const args: string[] = [];

				if (jsonOutput) {
					args.push('--json-output');
				}

				switch (operation) {
					case 'scan':
						args.push('scan');
						break;
					case 'piiScan':
						args.push('pii', 'scan');
						break;
					case 'piiRedact':
						args.push('pii', 'redact');
						break;
					default:
						throw new NodeOperationError(
							this.getNode(),
							`Unknown operation: ${operation}`,
							{ itemIndex: i },
						);
				}

				// Escape the input text for shell safety
				const escapedText = inputText.replace(/"/g, '\\"');
				args.push(`"${escapedText}"`);

				const command = `${cliPath} ${args.join(' ')}`;

				const stdout = execSync(command, {
					encoding: 'utf-8',
					timeout: 30000,
					maxBuffer: 1024 * 1024,
				});

				if (jsonOutput) {
					try {
						const parsed = JSON.parse(stdout.trim());
						returnData.push({ json: parsed });
					} catch {
						// If JSON parsing fails, return raw output
						returnData.push({
							json: {
								raw: stdout.trim(),
								operation,
								success: true,
							},
						});
					}
				} else {
					returnData.push({
						json: {
							output: stdout.trim(),
							operation,
							success: true,
						},
					});
				}
			} catch (error) {
				if (error instanceof NodeOperationError) {
					throw error;
				}

				const message = error instanceof Error ? error.message : String(error);

				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: message,
							success: false,
						},
					});
					continue;
				}

				throw new NodeOperationError(this.getNode(), message, {
					itemIndex: i,
				});
			}
		}

		return [returnData];
	}
}
