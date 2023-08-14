<script>
export let data
export let form

import {
		ButtonGroup,
		Drawer,
		Table,
		TableHead,
		TableHeadCell,
		TableBody,
		TableBodyRow,
		TableBodyCell,
		Select
	} from 'flowbite-svelte';

    import { Button, Modal, Label, Input } from 'flowbite-svelte';
    let values = [
    {
      "ip_or_hostname": ""
    }
  ];

  const addField = () => {
    values = [...values, { ip_or_hostname: "" }];
  };

  const removeField = () => {
    values = values.slice(0, values.length - 1);
  };
    </script>

<form class="flex flex-col space-y-6" action="?/submit" method="POST">
    <h3 class="mb-4 text-xl font-medium text-gray-900 dark:text-white">Scan IPs & Hosts</h3>
    {#each values as value, i}
    <Label class="space-y-2">
        <span>IP or Host (eg. 34.117.168.233 or www.google.com')</span>
        <Input type="text" name="ip_or_hostname" required />
    </Label>
    {/each}
    {#if values.length > 1}
    <Button type="button" color="red" on:click={removeField}>Remove Field</Button>
    {/if}
    <Button type="submit" color="red" class="w-full1">Submit</Button>
    <Button type="button" color="red" on:click={addField}>Add Field</Button>
</form>

<!-- todo: needs refactor. this was coppied from another application -->
<div class="results-tables">
<Table >
  <TableHead>
    <TableHeadCell>Host</TableHeadCell>
    <TableHeadCell>IP</TableHeadCell>
    <TableHeadCell>Scan Time</TableHeadCell>
    <TableHeadCell>Ports</TableHeadCell>
    <TableHeadCell>Historical Scan Data</TableHeadCell>
  </TableHead>
  <TableBody>
    {#if form?.success}
      {#each form.data.scan_results as result}
        <TableBodyRow>
          <TableBodyCell>{result.host}</TableBodyCell>
          <TableBodyCell>{result.ip}</TableBodyCell>
          <TableBodyCell>{result.scan_time}</TableBodyCell>
          <TableBodyCell>
            {#each Object.entries(result.ports) as [port, status]}
              <span>{port}: {status}</span>
            {/each}
          </TableBodyCell>
          <TableBodyCell>
            {#each form.data.historical_scan_data.ip_scan_history as history}
              {#if history.ip === result.ip}
                {#each history.port as port}
                  <div>
                    <span>Port {port.port_number}:</span>
                    {#each port.history as scan}
                      <span>{scan.time}: {scan.status}</span>
                    {/each}
                  </div>
                {/each}
              {/if}
            {/each}
          </TableBodyCell>
        </TableBodyRow>
      {/each}
    {:else}
      <TableBodyRow>
        <TableBodyCell colspan="5">No scan results found</TableBodyCell>
      </TableBodyRow>
    {/if}
  </TableBody>
</Table>
</div>
<style>
    /* add some styling so that the form is centered and has width about a third of the screen */
    form {
        width: 30%;
        margin: 0 auto;
    }
    /* center the table like we did the form */
    .results-tables {
        width: 30%;
        margin: 0 auto;
    }
</style>