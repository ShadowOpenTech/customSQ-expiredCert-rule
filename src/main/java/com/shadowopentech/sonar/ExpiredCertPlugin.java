package com.shadowopentech.sonar;

import org.sonar.api.Plugin;

/**
 * Entry point for the Expired Certificate SonarQube plugin.
 * Registers all extensions: rules definition, sensor, and configurable properties.
 */
public class ExpiredCertPlugin implements Plugin {

    @Override
    public void define(Context context) {
        context.addExtension(ExpiredCertSensor.class);
        context.addExtensions(java.util.Arrays.asList(ExpiredCertRulesDefinition.propertyDefinitions()));
    }
}
