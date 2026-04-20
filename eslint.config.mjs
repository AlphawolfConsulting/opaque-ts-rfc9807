import eslintJS from '@eslint/js'
import eslintTS from 'typescript-eslint'
import pluginPrettier from 'eslint-plugin-prettier/recommended'
import pluginSecurity from 'eslint-plugin-security'
import pluginJest from 'eslint-plugin-jest'
import pluginFunctional from 'eslint-plugin-functional'

export default eslintTS.config(
    eslintJS.configs.recommended,
    ...eslintTS.configs.strictTypeChecked,
    pluginJest.configs['flat/recommended'],
    pluginSecurity.configs.recommended,
    {
        ignores: [
            'jest.config.mjs',
            'eslint.config.mjs',
            'rollup.config.js',
            'coverage/*',
            'dist/*',
            'lib/*'
        ]
    },
    {
        languageOptions: {
            sourceType: 'module',
            parserOptions: {
                project: true,
                tsconfigRootDir: import.meta.dirname
            }
        },
        plugins: {
            functional: pluginFunctional
        },
        rules: {
            '@typescript-eslint/no-namespace': 'warn',
            '@typescript-eslint/no-unused-vars': [
                'error',
                {
                    args: 'all',
                    argsIgnorePattern: '^_',
                    caughtErrors: 'all',
                    varsIgnorePattern: '^_'
                }
            ],
            '@typescript-eslint/consistent-type-imports': 'error',
            '@typescript-eslint/consistent-type-exports': 'error',
            '@typescript-eslint/restrict-template-expressions': 'off',

            // Functional programming rules
            'no-param-reassign': 'error',
            'no-var': 'error',
            'prefer-const': 'error',
            'functional/immutable-data': 'warn',
            'functional/no-class': 'off',
            'functional/prefer-readonly-type': 'warn',

            // Side effect warnings
            'no-console': ['warn', { allow: ['warn', 'error'] }],
            'no-alert': 'error',

            // Complexity limits
            complexity: ['warn', 10],
            'max-lines-per-function': [
                'warn',
                { max: 50, skipBlankLines: true, skipComments: true }
            ],
            'max-depth': ['warn', 3]
        }
    },
    pluginPrettier
)
