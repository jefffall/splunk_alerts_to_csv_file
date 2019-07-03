import re,sys,time
import splunk.Intersplunk
import os, fnmatch
import traceback



alert_settings = {}
alert_unique_dictionary = {}

alerts_array_dict = []

# This list will hold the final alert values as { 'heading ' : 'value', heading2 : value2 ... }
parsed_final_alert_for_csv = []


process_alert_name = "First Alert Not Processed"
process_alert = False

    
def output_csv(array_of_dict_alerts):
    
    try:
    

        for d in array_of_dict_alerts:
            enabled = d.get('enableSched')
            if (enabled == "1"):
                alert_enabled = "YES"
            else: 
                alert_enabled = "NO"
        
            search_string = d.get('search')
        
            earliest = d.get('dispatch.earliest_time')
            latest =  d.get('dispatch.latest_time')
            quantity = d.get('quantity')
        
            sign = ""
            relation = d.get('relation')
            if (relation == "greater than"):
                sign = ">"
            elif  (relation == "less than"):
                sign = "<"
            elif  (relation == "equal to"):
                sign = "="
            elif  (relation == "not equal to"):
                sign = "!="
            elif  (relation == "drops by"):
                sign = "drops by"
            elif  (relation == "rises by"):
                sign = "^ by"   
            
            counttype = d.get('counttype')
            quantity = d.get('quantity')
            trigger_on = counttype + " " + sign + " " + quantity
        
            throttle = d.get('alert.suppress')
            #delay = "OFF"
            if (throttle == "1"):
                delay = d.get('alert.suppress.period')
            else:
                delay = "OFF"
            
            email_options = ""
            email_addr = "No"
           
            send_email = d.get('action.email')
            if (send_email == "1"):
                
                include_search = d.get('action.email.include.search')
                if (include_search == "1"):
                    email_options = "inc search> "
        
                include_trigger = d.get('action.email.include.trigger')
                if (include_trigger == "1"):
                    email_options = email_options + "inc trig> "
        
                include_trigger_time = d.get('action.email.include.trigger_time')
                if (include_trigger_time == "1"):
                    email_options = email_options + "trig time> "
        
                inline = d.get('action.email.inline')
                if (inline == "1"):
                    email_options = email_options + "res inline> "
        
                priority = d.get(' action.email.priority')
                if (priority == "1"):
                    email_options = email_options + "pri> "
        
                sendcsv = d.get('action.email.sendcsv')
                if (sendcsv == "1"):
                    email_options = email_options + "sendcsv> "
        
                sendpdf = d.get('action.email.sendpdf')
                if (sendpdf == "1"):
                    email_options = email_options + "sendPDF> "
        
                send_results = d.get('action.email.sendresults')
                if (send_results == "1"):
                    email_options = email_options + "sendRESU> "
             
                email_addr = d.get('action.email.to')
           
            else:
                email_addr = "NO"
            
            add_to_triggered_alerts = d.get('alert.track')
            if (add_to_triggered_alerts == "1"):
                added_to_triggered_alerts = "Alert Tracked"
            else:
                added_to_triggered_alerts = " "
        
            webhook = d.get('action.webhook')
            if (webhook == "1"):
                webhook_url = d.get('action.webhook.param.url')
            else:
                webhook_url = " "
        
            log_event_items = "" 
            logevent = d.get('action.logevent')   
            if (logevent == "1"):
                logged_event_name = d.get('action.logevent.param.event')
                log_event_items = log_event_items + logged_event_name
                logged_event_host = d.get('action.logevent.param.host')
                log_event_items = log_event_items + " to " + logged_event_host
            
          
        
            telemetry_string = ""
            outputtelemetry = d.get('action.outputtelemetry')
            if (outputtelemetry == "1"):
            
          
            
                tinput = d.get('action.outputtelemetry.param.input')
                if tinput is not None:
                    telemetry_string =  telemetry_string + " " + tinput
           
                optinrequired = d.get('action.outputtelemetry.param.optinrequired')
                if optinrequired is not None:
                    if (optinrequired == "1"):
                        requiredopt = "Splunk 6.5"
                    elif  (optinrequired == "2"):
                        requiredopt = "Splunk 6.6"
                    elif  (optinrequired == "3"):
                        requiredopt = "Splunk 7.0"
                    else:
                        requiredopt = ""
                    telemetry_string =  telemetry_string + " " + requiredopt
           
                teletype = d.get('action.outputtelemetry.param.type')
                if teletype is not None:
                    telemetry_string =  telemetry_string + " " + teletype
                
                component = d.get(' action.outputtelemetry.param.component')
                if component is not None:
                    telemetry_string =  telemetry_string + component
           
                 
            lookup_filename = " "
            file_action = " "   
            lookup = d.get('lookup')
            if (lookup == "1"):
                lookup_filename = d.get('action.lookup.filename')
                lookup_filename = lookup_filename.strip()
                append = d.get('action.lookup.append')
                if (append == "1"): 
                     file_action = "append"
                else:
                    file_action = "replace"   
        
#      splunk.Intersplunk.outputResults("Alert Name,CRON,Alert Enabled,SEARCH STRING:,Earliest,Latest,Trigger Alert On:,Throttle,Send Email,Triggered Alerts,Webhook,Logged Event,output to lookup/csv,telemetry\n")
            email_settings = email_options+" To "+email_addr
 
            local_dict = {}
            local_dict = {'Alert Name' : d['alert_name'], 'CRON' : d['cron_schedule'], 'Alert Enabled':alert_enabled, 'SEARCH STRING':search_string, 'Earliest':earliest, 'Latest':latest, 'Trigger Alert On:':trigger_on, 'Throttle':delay, 'Send Email':email_settings, 'Triggered Alerts':added_to_triggered_alerts, 'Webhook':webhook_url, 'Logged Event':log_event_items, 'output to lookup csv':lookup_filename, 'telemetry':telemetry_string}

            parsed_final_alert_for_csv.append(local_dict) 
#        splunk.Intersplunk.generateErrorResults(local_dict)
    #except Exception as e:
    except:
            tracestack = traceback.format_exc()
            splunk.Intersplunk.generateErrorResults(tracestack)
            exit(0)
        
    finally:
        pass
         
         
def find_paths(fileList):
    
    inDIR = '../..'
    pattern = 'savedsearches.conf'
    #filelist = []
    
    
    #walk t hru directory
    for dName, sdname, fList in os.walk(inDIR):   
            
            
        for fileName in fList:
            if fnmatch.fnmatch(fileName, pattern): # Match namwe string
                if ((not "splunk_archiver" in dName) and (not "splunk_monitoring_console" in dName) and (not "splunk_instrumentation" in dName) and (not "search/default" in dName)):
                    fileList.append({'path to savedsearch.conf' : os.path.join(dName, fileName)})
    
    return (fileList)

path_to_savedsearches_conf = ""        

try:
    keywords,options = splunk.Intersplunk.getKeywordsAndOptions()
    defaultval = options.get('default', None)
    field = options.get('field', '_raw')
    
    if len(keywords) != 1:
            splunk.Intersplunk.generateErrorResults('Requires exactly one argument. either the word "list" or "help" or a relative path to the savedsearches.conf file')
            exit(0)
            
    if (keywords[0] == "list"):
        saved_searches = []     
        saved_searches = find_paths(saved_searches)  
        splunk.Intersplunk.outputResults(saved_searches)
        exit(0) 
        
    if ((keywords[0] == "help") or (keywords[0] == "?")):
            
        help_line = []
        help_line.append({ 'help' : '--------------------- Help for alert_to_csv_file app -------------------'}) 
        help_line.append({ 'help' : ' '})
        help_line.append({ 'help' : 'Use this app alerts_to_csv_file to dump out your user defined alerts into a .csv file and open with Excel or similar'})
        help_line.append({ 'help' : ' '})
        help_line.append({ 'help' : 'Workflow steps:'})
        help_line.append({ 'help' : '1) Issue this command: | exportalerts list'})
        help_line.append({ 'help' : 'This will give you a list of user defined alert directory paths on Splunk cloud or your on-prem splunk instance'})
        help_line.append({ 'help' : 'Example of directory listing: ../../search/local/savedsearches.conf which is a relative path to your saved searches'})
        help_line.append({ 'help' : 'Now highlight the relative directory path: ../../search/local/savedsearches.conf and right click the mouse and do a copy or use control C in windows'})
        help_line.append({ 'help' : 'in the search bar now simply type: | exportalerts ../../search/local/savedsearches.conf by pasting in the path and hit enter'})
        help_line.append({ 'help' : ' '})
        help_line.append({ 'help' : 'The export_alerts_to_csv_file will now list your alerts'})
        help_line.append({ 'help' : '2) In the top right use SAVE As to save this search as a REPORT. Name the report some name you choose'})
        help_line.append({ 'help' : '3) In the upper right of the export_alerts_to_csv app is a dropdown showing "Default Views"'})
        help_line.append({ 'help' : '4) Use the drop-down arrow and select "REPORTS"'})
        help_line.append({ 'help' : '5) Find the report you just created - find the name you used...'})
        help_line.append({ 'help' : '6) You will see all your alerts below. Now find the Export arrow far upper right. Arrow points to a horizonal line. Hover over and see "Export"'})
        help_line.append({ 'help' : '7) In the dialogue box keep CSV. Name the file. Leave Number of results blank. The CSV file will now download to your downloads folder'}) 
        help_line.append({ 'help' : '8) Open the .csv file with Excel or Apple Numbers or app of your choice. Enjoy.'})
        help_line.append({ 'help' : 'Support- email devopsjeffreyfall@gmail.com send any errors or any comments'})
        
        
        
        splunk.Intersplunk.outputResults(help_line)
        exit(0)
    
    else:
        if (not "savedsearches.conf" in keywords[0]):
            splunk.Intersplunk.generateErrorResults('the path you entered does not contain the string "savedsearches.conf". Nope - no snooping other files allowed out of context. Try again. use | exportalerts list or | exportalerts help')
            exit(0)
            
        path_to_savedsearches_conf = keywords[0]
        
#except:
    #tracestack = traceback.format_exc()
    #splunk.Intersplunk.generateErrorResults(tracestack)
    #exit(0)
finally:
    pass

 
  
  ################################################################################################################################
  # Process savedsearches.conf file
  ################################################################################################################################
  
       
#filehandle = open("/home/jfall/local_saved_searches.txt", "r")
filehandle = open(path_to_savedsearches_conf, "r")
for item in filehandle:
    first = item[:1]
    
    if (first == "#"):
        break
    
    if (first == "["): # Here we have a valid alert
       
        if (process_alert_name == "First Alert Not Processed"):
            saved_search_name=item[item.find("[")+1:item.find("]")]
            process_alert_name="First Alert Now Processed..."
            #print "first alert processed"
        elif (process_alert_name  != "First Alert Not Processed"):
            process_alert_name = saved_search_name
            saved_search_name=item[item.find("[")+1:item.find("]")]
            process_alert = True                  
    
    else:
        try:
            special_case = item[0:8]
            if (special_case == "search ="):
                value = item[8:]
                alert_settings['search'] = value.strip()
                alert_unique_dictionary['search'] = value.strip()
            else:
                item = item.strip()
                my_pair = item.split("=",1)
                
                if (len(my_pair) == 2 ):
                
                    my_field = my_pair[0]
                    my_value = my_pair[1]
                
                    my_field = my_field.strip()
                    my_value = my_value.strip()
                
                    alert_settings[my_field] = my_value
                    alert_unique_dictionary[my_field] = my_value
                
                # Not a user type alert so ignore it and trash the line    
                #else:
                #    splunk.Intersplunk.generateErrorResults(my_pair)
                #    exit(0)
                #   my_list_string = ''.join(my_pair)
                #   my_error_string = "Parse alert: Alert pair not recognised. Notify developer." . my_list_string
                #    splunk.Intersplunk.generateErrorResults(my_error_string)
                #    exit(0)
                    
                
           
       
        except:
            tracestack = traceback.format_exc()
            splunk.Intersplunk.generateErrorResults(tracestack)
            exit(0)
        
  
  
    if (process_alert == True):
        
        alert_settings['alert_name'] = process_alert_name.strip()
        alerts_array_dict.append(alert_settings)
        
        
#        print alert_settings
#        print_alert(process_alert_name, cron_schedule)
        process_alert = False
        alert_settings = {}
        
alert_settings['alert_name'] = saved_search_name.strip()
alert_unique_dictionary['alert_name'] = saved_search_name.strip()
alerts_array_dict.append(alert_settings)
#print alert_settings

#print "\n\n\n\n\n"
#alert_unique_dictionary_sorted = sorted(alert_unique_dictionary)

  
output_csv(alerts_array_dict)

#splunk.Intersplunk.generateErrorResults(alerts_array_dict)


#splunk.Intersplunk.outputResults(alerts_array_dict)
splunk.Intersplunk.outputResults(parsed_final_alert_for_csv)
