module.exports = {
  dependency: {
    platforms: {
      android: {
        sourceDir: './android',
        packageImportPath: 'import com.shieldsdk.rasp.reactnative.RaspShieldPackage;',
        packageInstance: 'new RaspShieldPackage()',
      },
    },
  },
};
