import nodeResolve from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';

const external = ['@shgysk8zer0/polyfills'];
const modules = [
	'consts',
	'env',
	'firebase',
	'jwk-utils',
	'jwk',
	'jwt',
	'origin-tokens',
	'utils',
];
const plugins = [nodeResolve()];
const outputPlugins = [terser()];

export default modules.map(module => ({
	input: `${module}.js`,
	external,
	plugins,
	output: [{
		file: `${module}.cjs`,
		format: 'cjs',
		exports: 'named',
	}, {
		file: `${module}.min.js`,
		format: 'esm',
		plugins: outputPlugins,
		sourcemap: 'external',
	}]
}));
