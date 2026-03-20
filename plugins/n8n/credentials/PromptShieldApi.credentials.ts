import type {
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class PromptShieldApi implements ICredentialType {
	name = 'promptShieldApi';
	displayName = 'Prompt Shield';
	documentationUrl = 'https://github.com/mthamil107/prompt-shield';

	properties: INodeProperties[] = [
		{
			displayName: 'CLI Binary Path',
			name: 'pythonPath',
			type: 'string',
			default: 'prompt-shield',
			placeholder: 'prompt-shield',
			description:
				'Path to the prompt-shield CLI binary. Use "prompt-shield" if installed globally, or provide the full path to the executable.',
		},
	];
}
