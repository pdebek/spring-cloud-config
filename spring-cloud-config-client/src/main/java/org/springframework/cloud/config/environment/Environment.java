/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.cloud.config.environment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Simple plain text serializable encapsulation of a list of property sources. Basically a
 * DTO for {@link org.springframework.core.env.Environment}, but also applicable outside
 * the domain of a Spring application.
 * 
 * @author Dave Syer
 *
 */
public class Environment {

    private String application;

	private String name;

	private String label;

	private List<PropertySource> propertySources = new ArrayList<PropertySource>();

    public Environment(String name, String label) {
        this.name = name;
        this.label = label;
    }

    @JsonCreator
    public Environment(@JsonProperty("application") String application,
                       @JsonProperty("name") String name,
                       @JsonProperty("label") String label) {
        this.application = application;
        this.name = name;
        this.label = label;
    }

    public void add(PropertySource propertySource) {
        this.propertySources.add(propertySource);
	}

	public void addFirst(PropertySource propertySource) {
		this.propertySources.add(0, propertySource);
	}

	public List<PropertySource> getPropertySources() {
		return propertySources;
	}

    public String getApplication() {
        return application;
    }

	public String getName() {
		return name;
	}

	public String getLabel() {
		return label;
	}

	@Override
	public String toString() {
		return "Environment [application=" + application + ", name=" + name + ", label=" + label + ", propertySources="
				+ propertySources + "]";
	}
}
