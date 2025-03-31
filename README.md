# Android Static Analyzer

## Overview

Android Static Analyzer is a tool that performs static analysis on Android applications (.apk files) to extract information about sensitive API usage and control flow. The analyzer produces two main outputs:

1. **Control-flow graphs (CFGs)**: For each function in the application, a CFG is generated in the DOT format, which can be visualized using tools like Graphviz.

2. **Sensitive API usage information**: The tool identifies API calls that require specific Android permissions (as defined in a provided CSV file) and outputs a report detailing these calls, their frequency, and where they occur in the code.

## Implementation Details

### Core Components

The analyzer is built on the [Soot](https://github.com/soot-oss/soot) framework, a Java optimization framework that provides tools for analyzing and transforming Java bytecode. The main components of the analyzer include:

1. **Soot Configuration**: Sets up Soot to analyze Android applications by configuring the appropriate options for APK processing.

2. **Call Graph Construction**: Uses Class Hierarchy Analysis (CHA) to build a call graph representing the relationships between methods in the application.

3. **Control-flow Graph Generation**: For each method in the application, generates a control-flow graph representing the possible execution paths.

4. **Sensitive API Detection**: Identifies method calls to APIs that require specific Android permissions by checking against a provided list of sensitive APIs.

5. **Output Generation**: Produces DOT files for CFGs and a text file containing sensitive API usage information.

### Algorithm

The analyzer performs the following steps:

1. Loads sensitive API information from a CSV file.
2. Configures Soot for APK processing and builds a call graph.
3. Processes each application class and method:
    - Generates a control-flow graph for each method
    - Analyzes the method body to identify sensitive API calls
4. Outputs the results to the specified directory.

## Setup

### Prerequisites

- Java Development Kit (JDK) 11 or later
- Maven for dependency management
- Graphviz (optional, for visualizing the generated DOT files)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/tropicbliss/android-static-analyzer.git
   cd android-static-analyzer
   ```

2. Build the project with Maven:
   ```
   mvn clean package
   ```

### Setting up the Android Platforms Directory

The analyzer requires access to the Android platform libraries to properly analyze Android applications. The `platforms` directory contains the Android SDK platform JARs for different API levels.

#### What is the platforms directory?

The `platforms` directory is a collection of subdirectories, each named after an Android API level (e.g., `android-25`, `android-26`, etc.), containing the corresponding `android.jar` file. These JAR files provide the class definitions and method signatures for Android framework APIs at specific API levels.

#### How to set it up:

1. **Option 1: Using an existing Android SDK installation**:

   If you already have the Android SDK installed, you can create a symbolic link to the platform directories:

   ```bash
   ln -s $ANDROID_SDK_HOME/platforms platforms
   ```

   Replace `$ANDROID_SDK_HOME` with the path to your Android SDK installation.

2. **Option 2: Manual setup**:

   Create a directory structure as follows:

   ```
   platforms/
   ├── android-19/
   │   └── android.jar
   ├── android-21/
   │   └── android.jar
   ├── android-23/
   │   └── android.jar
   ...
   ```

   You can download the `android.jar` files from the Android SDK or from various online repositories.

3. **Option 3: Using the Android SDK Manager**:

   Install the necessary platform versions using the Android SDK Manager:

   ```bash
   sdkmanager "platforms;android-25" "platforms;android-26" "platforms;android-27"
   ```

   Then create the symbolic link as in Option 1.

#### Path Configuration

The analyzer is configured to look for the `platforms` directory in the working directory by default. If you want to use a different location, you can modify the `configureSoot` method in the `AndroidStaticAnalyzer.java` file:

```java
Options.v().set_android_jars("/path/to/your/platforms");
```

## Usage

### Running the Analyzer

Run the analyzer using the following command:

```
java -jar target/android-static-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar <apk-file> <sensitive-apis-csv>
```

#### Parameters:

- `<apk-file>`: Path to the Android APK file to analyze
- `<sensitive-apis-csv>`: Path to the CSV file containing sensitive API information

### CSV Format

The CSV file should contain information about sensitive APIs in the following format:

```
CallerClass,CallerMethod,Permission
```

For example:

```
com/android/server/LocationManagerService,getProviders,android.permission.ACCESS_COARSE_LOCATION
com/android/server/LocationManagerService,getBestProvider,android.permission.ACCESS_COARSE_LOCATION
com/android/server/LocationManagerService,addGpsStatusListener,android.permission.ACCESS_COARSE_LOCATION
```

You can use `/assets/sensitive_apis.csv` as a starting point.

## Output

### Output Directory Structure

The analyzer generates output files in the `output` directory:

```
output/
├── ClassName1_methodName1.dot
├── ClassName1_methodName2.dot
├── ClassName2_methodName1.dot
...
└── sensitive_api_usage.txt
```

### Control-flow Graphs (DOT Files)

Each `.dot` file represents the control-flow graph for a specific method. You can visualize these files using Graphviz:

```
dot -Tpng output/ClassName_methodName.dot -o output/ClassName_methodName.png
```

### Sensitive API Usage Report

The `sensitive_api_usage.txt` file contains information about sensitive API usage in the following format:

```
API_name:frequency:residing functions
```

For example:

```
getLastLocation:2:com.example.app.MainActivity.onCreate(),com.example.app.LocationService.updateLocation()
isProviderEnabled:3:com.example.app.MainActivity.onResume(),com.example.app.MainActivity.onResume(),com.example.app.MainActivity.onResume()
```

This indicates:
- `getLastLocation` is called twice in the application, once in `MainActivity.onCreate()` and once in `LocationService.updateLocation()`
- `isProviderEnabled` is called three times in `MainActivity.onResume()`

## Example Analysis

Here's an example output of analyzing a location-based Android application:

```
Starting analysis of APK: demo.apk
Loading sensitive APIs from: sensitive_apis.csv
Loaded 99 permissions with 28809 sensitive APIs.
Permission: android.permission.MODIFY_PHONE_STATE has 17 APIs
Permission: android.permission.INTERACT_ACROSS_USERS has 9020 APIs
...
Configuring Soot...
Analyzing the APK...
Building call graph...
Call graph built successfully.
Call graph verification successful.
Processing application classes...
Processed 7 classes, 15 methods, analyzed 15 method bodies.
Generating output files...
Found 10 unique sensitive APIs with a total of 12 calls. Results written to output\sensitive_api_usage.txt
Analysis completed successfully. Check the output directory for results.
```

## Technical Details

### Managing Special Method Names

The analyzer handles special method names like constructors (`<init>`) and static initializers (`<clinit>`) by sanitizing them for filenames:
- `<init>` becomes `constructor`
- `<clinit>` becomes `static_initializer`

### Error Handling and Recovery

The analyzer includes robust error handling to ensure that:
- Issues with individual methods don't prevent analysis of the entire application
- Problems with call graph construction fall back to direct method analysis
- Invalid filenames are sanitized to prevent file system errors

## Troubleshooting

### Memory Issues

If you encounter `OutOfMemoryError`, increase the Java heap size:

```
java -Xmx4g -jar target/android-static-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar <apk-file> <sensitive-apis-csv>
```

### Android Platform Issues

If you see errors related to missing Android classes, ensure your `platforms` directory is set up correctly and contains the appropriate API level JARs for the APK you're analyzing.

### Slow Analysis

For large APKs, the analysis might take significant time. Consider:

1. Increasing the heap size as mentioned above
2. Using the `-exclude` option in the code to exclude more packages
3. Analyzing only specific components of interest

## References

- [Soot Framework](https://github.com/soot-oss/soot)
- [Android API Documentation](https://developer.android.com/reference)
- [DOT File Format](https://en.wikipedia.org/wiki/DOT_(graph_description_language))