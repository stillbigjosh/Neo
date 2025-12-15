# NeoC2 Reporting System - CLI Guide

## Table of Contents
- [Overview](#overview)
- [Command Structure](#command-structure)
- [Available Reports](#available-reports)
- [Basic Commands](#basic-commands)
- [Advanced Usage](#advanced-usage)
- [Export Functionality](#export-functionality)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Overview

### Key Features
- Real-time report generation
- Filtering by date range, agent ID, and user ID
- Multiple export formats (CSV, JSON)
- Comprehensive data analysis capabilities
- Integration with NeoC2's database system

## Command Structure

The reporting system follows this basic command structure:

```
reporting <action> [report_type] [options]
```

### Available Actions
- `list` - Display available report types
- `<report_type>` - Generate a specific report
- `export` - Export a report in a specific format

### Options
- `start_date=YYYY-MM-DD` - Filter data starting from this date
- `end_date=YYYY-MM-DD` - Filter data ending at this date
- `agent_id=<agent_id>` - Filter data for a specific agent
- `user_id=<user_id>` - Filter data for a specific user

## Available Reports

### 1. Agent Activity Report (`agent_activity`)
Provides comprehensive information about agent activity, communication patterns, task execution, and result generation.

**Data includes:**
- Agent identification and metadata
- Task counts (total, completed)
- Result counts
- Status information
- Connection timestamps

### 2. Task Execution Report (`task_execution`)
Detailed report of task execution, including status, timing, and results.

**Data includes:**
- Task ID and agent association
- Command executed
- Status (pending, completed, failed)
- Creation and completion timestamps
- Module ID if applicable

### 3. Audit Log Report (`audit_log`)
Security audit log tracking user actions and system events.

**Data includes:**
- User identification
- Action performed
- Resource type and ID
- Timestamp of events
- IP addresses
- Action details

### 4. Module Usage Report (`module_usage`)
Report on module usage patterns and execution frequency.

**Data includes:**
- Module names and descriptions
- Execution counts
- Usage statistics
- Module metadata

### 5. System Overview Report (`system_overview`)
Comprehensive system health and configuration report.

**Data includes:**
- System statistics (agents, tasks, modules, users)
- Recent activity
- System status
- Resource utilization metrics

## Basic Commands

### List Available Reports
```
reporting list
```
Displays all available report types with descriptions.

### Generate Agent Activity Report
```
reporting agent_activity
```
Generates a report of all agent activity without any filters.

### Generate Task Execution Report
```
reporting task_execution
```
Generates a report of all task executions without any filters.

### Generate Audit Log Report
```
reporting audit_log
```
Generates a security audit log report without any filters.

### Generate Module Usage Report
```
reporting module_usage
```
Generates a report of module usage without any filters.

### Generate System Overview Report
```
reporting system_overview
```
Generates a comprehensive system overview report.

## Advanced Usage

### Filtering by Date Range
Generate reports for specific time periods:

```
reporting agent_activity start_date=2024-01-01 end_date=2024-12-31
reporting task_execution start_date=2024-06-01 end_date=2024-06-30
reporting audit_log start_date=2024-01-01
```

### Filtering by Agent ID
Generate reports for specific agents:

```
reporting agent_activity agent_id=AGENT001
reporting task_execution agent_id=AGENT001
reporting audit_log agent_id=AGENT001
```

Note: For the audit log report, the agent_id filter will match logs related to the specified agent either by resource ID or in the details field.

### Combining Filters
You can combine multiple filters for more specific reporting:

```
reporting task_execution agent_id=AGENT001 start_date=2024-06-01 end_date=2024-06-30
reporting audit_log user_id=USER001 start_date=2024-01-01 end_date=2024-12-31
```

### Multiple Options
You can specify multiple options in a single command:

```
reporting task_execution agent_id=AGENT001 start_date=2024-06-01 end_date=2024-06-30
```

## Export Functionality

The reporting system supports exporting data in multiple formats for further analysis or archival purposes.

### Export Command Structure
```
reporting export <report_type> <format> [options]
```

### Supported Formats
- `csv` - Comma-separated values format for spreadsheet applications
- `json` - JavaScript Object Notation format for programmatic processing

### Examples

#### Export Agent Activity to CSV
```
reporting export agent_activity csv
```

#### Export Task Execution to JSON
```
reporting export task_execution json
```

#### Export Filtered Report to CSV
```
reporting export task_execution csv start_date=2024-01-01 end_date=2024-12-31 agent_id=AGENT001
```

#### Export Filtered Report to JSON
```
reporting export audit_log json start_date=2024-06-01 end_date=2024-06-30
```

## Examples

### Basic Examples

1. **List all available reports:**
   ```
   reporting list
   ```

2. **Get overall agent activity:**
   ```
   reporting agent_activity
   ```

3. **Get system overview:**
   ```
   reporting system_overview
   ```

### Filtered Examples

4. **Get agent activity for specific agent:**
   ```
   reporting agent_activity agent_id=AGENT001
   ```

5. **Get task execution for specific date range:**
   ```
   reporting task_execution start_date=2024-06-01 end_date=2024-06-30
   ```

6. **Get audit logs for specific user in June 2024:**
   ```
   reporting audit_log user_id=USER001 start_date=2024-06-01 end_date=2024-06-30
   ```

### Export Examples

7. **Export all module usage to CSV:**
   ```
   reporting export module_usage csv
   ```

8. **Export filtered task execution to JSON:**
   ```
   reporting export task_execution json start_date=2024-01-01 end_date=2024-12-31
   ```

9. **Export specific agent's activity to CSV:**
   ```
   reporting export agent_activity csv agent_id=AGENT001 start_date=2024-06-01
   ```

### Complex Filtering Examples

10. **Get comprehensive report for specific agent and time period:**
    ```
    reporting agent_activity agent_id=AGENT001 start_date=2024-01-01 end_date=2024-12-31
    ```

11. **Export system-critical audit logs:**
    ```
    reporting export audit_log csv start_date=2024-11-01 end_date=2024-11-30
    ```

12. **Get module usage for specific user within date range:**
    ```
    reporting module_usage start_date=2024-10-01 end_date=2024-10-31
    ```

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Invalid report type" error
**Cause:** Report type is misspelled or not available
**Solution:** Use `reporting list` to see available report types

#### Issue: "Error generating report" error
**Cause:** Database connection issue or invalid parameters
**Solution:** Check date formats (YYYY-MM-DD) and ensure agent/user IDs are valid

#### Issue: Report returns "No results found"
**Cause:** No data exists for the specified filters
**Solution:** Try broadening your search criteria or verify date ranges

### Performance Considerations

- Large date ranges may impact performance
- Filtering by specific agent ID or user ID typically performs better than broad queries
- Export operations process all data before formatting, so they may take longer than display operations
- The audit log report is limited to 1000 entries by default for performance reasons

## Security Notes

- All reporting operations respect the current user's permissions
- Sensitive information in reports is subject to the user's access level
- Audit logs track all report generation activities for compliance purposes
- Exported data should be handled according to your organization's data classification policies

## Integration with Other Features

The reporting system works seamlessly with other NeoC2 features:
- Reports can be generated during interactive agent sessions
- Filtering can be combined with agent management commands
- Exported data can be used with external analysis tools
- Reporting can be integrated into automated workflows
